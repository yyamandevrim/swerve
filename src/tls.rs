use crate::config::BypassStrategy;
use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy)]
pub struct DesyncOptions {
    pub strategy: BypassStrategy,
    pub chunk_size: usize,
    pub chunk_delay_us: u64,
    pub fake_count: u8,
    pub fake_ttl: u8,
}

/// Reads the initial bytes from `client`. If they start with a TLS Handshake record (`0x16 0x03`),
/// reads the complete first TLS record (up to 18 KiB) so ClientHello can be fragmented cleanly.
pub async fn read_initial_client_hello(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    let n = client.read(&mut header).await?;
    if n == 0 {
        return Ok(Vec::new());
    }
    if n < 5 {
        return Ok(header[..n].to_vec());
    }

    if header[0] != 0x16 || header[1] != 0x03 {
        return Ok(header.to_vec());
    }

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len == 0 || record_len > 16384 + 2048 {
        return Ok(header.to_vec());
    }

    let mut buf = vec![0u8; 5 + record_len];
    buf[..5].copy_from_slice(&header);
    client.read_exact(&mut buf[5..]).await?;
    Ok(buf)
}

/// Locates the byte range `(start, end)` of the SNI hostname inside a raw TLS ClientHello record.
pub fn find_sni_range(record: &[u8]) -> Option<(usize, usize)> {
    if record.len() < 44 || record[0] != 0x16 || record[1] != 0x03 || record[5] != 0x01 {
        return None;
    }

    let mut pos = 5 + 4 + 2 + 32; // start of session_id_len

    let session_len = *record.get(pos)? as usize;
    pos += 1 + session_len;

    let cs_len = u16::from_be_bytes([*record.get(pos)?, *record.get(pos + 1)?]) as usize;
    pos += 2 + cs_len;

    let comp_len = *record.get(pos)? as usize;
    pos += 1 + comp_len;

    let ext_total = u16::from_be_bytes([*record.get(pos)?, *record.get(pos + 1)?]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(record.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            let name_type = record[pos + 2];
            let name_len = u16::from_be_bytes([record[pos + 3], record[pos + 4]]) as usize;
            let name_start = pos + 5;
            let name_end = name_start + name_len;
            if name_type == 0x00 && name_end <= pos + ext_len {
                return Some((name_start, name_end));
            }
        }
        pos += ext_len;
    }

    None
}

/// Splits a single TLS Handshake record into two valid TLS records at `payload_split_offset`.
pub fn split_tls_record(record: &[u8], payload_split_offset: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    if record.len() < 7 || record[0] != 0x16 || record[1] != 0x03 {
        return None;
    }
    let payload = &record[5..];
    if payload_split_offset == 0 || payload_split_offset >= payload.len() {
        return None;
    }

    let p1 = &payload[..payload_split_offset];
    let p2 = &payload[payload_split_offset..];

    let mut r1 = Vec::with_capacity(5 + p1.len());
    r1.extend_from_slice(&[record[0], record[1], record[2]]);
    r1.extend_from_slice(&(p1.len() as u16).to_be_bytes());
    r1.extend_from_slice(p1);

    let mut r2 = Vec::with_capacity(5 + p2.len());
    r2.extend_from_slice(&[record[0], record[1], record[2]]);
    r2.extend_from_slice(&(p2.len() as u16).to_be_bytes());
    r2.extend_from_slice(p2);

    Some((r1, r2))
}

/// Builds a benign minimal TLS ClientHello with a decoy SNI (`www.google.com`) for low-TTL DPI decoy injection.
pub fn build_decoy_client_hello(sni: &str) -> Vec<u8> {
    let h = sni.as_bytes();
    let mut sni_ext = Vec::new();
    let list_len = (1 + 2 + h.len()) as u16;
    sni_ext.extend_from_slice(&list_len.to_be_bytes());
    sni_ext.push(0x00);
    sni_ext.extend_from_slice(&(h.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(h);

    let mut exts = Vec::new();
    exts.extend_from_slice(&0x0000u16.to_be_bytes());
    exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_ext);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x53; 32]);
    body.push(0x00);
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = Vec::new();
    hs.push(0x01);
    let hs_len = body.len();
    hs.push(((hs_len >> 16) & 0xFF) as u8);
    hs.push(((hs_len >> 8) & 0xFF) as u8);
    hs.push((hs_len & 0xFF) as u8);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.extend_from_slice(&[0x16, 0x03, 0x01]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn set_socket_ttl(stream: &TcpStream, ttl: u8) {
    let fd = stream.as_raw_fd();
    let val: libc::c_int = ttl as libc::c_int;
    let is_v6 = stream.peer_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    unsafe {
        if is_v6 {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        } else {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TTL,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

async fn write_chunked(
    upstream: &mut TcpStream,
    data: &[u8],
    chunk_size: usize,
    chunk_delay_us: u64,
) -> io::Result<()> {
    let step = chunk_size.clamp(1, 256);
    for chunk in data.chunks(step) {
        upstream.write_all(chunk).await?;
        upstream.flush().await?;
        if chunk_delay_us > 0 {
            tokio::time::sleep(Duration::from_micros(chunk_delay_us)).await;
        }
    }
    Ok(())
}

/// Sends the ClientHello to `upstream` using the selected DPI bypass strategy & optional low-TTL decoy packets.
pub async fn send_desynced_client_hello(
    upstream: &mut TcpStream,
    raw: &[u8],
    opts: DesyncOptions,
) -> io::Result<()> {
    if raw.is_empty() || opts.strategy == BypassStrategy::Skip || raw.len() < 6 || raw[0] != 0x16 {
        upstream.write_all(raw).await?;
        upstream.flush().await?;
        return Ok(());
    }

    // Optional low-TTL decoy ClientHello injection for stricter ISP DPI boxes
    if opts.fake_count > 0 && opts.fake_ttl > 0 {
        let decoy = build_decoy_client_hello("www.google.com");
        let low_ttl = opts.fake_ttl.clamp(1, 32);
        set_socket_ttl(upstream, low_ttl);
        for _ in 0..opts.fake_count.min(5) {
            let _ = upstream.write_all(&decoy).await;
            let _ = upstream.flush().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        set_socket_ttl(upstream, 64);
    }

    let sni_mid = find_sni_range(raw)
        .map(|(s, e)| s + (e - s) / 2)
        .unwrap_or_else(|| (raw.len() / 2).max(6));

    match opts.strategy {
        BypassStrategy::Skip => {
            upstream.write_all(raw).await?;
            upstream.flush().await?;
        }
        BypassStrategy::Chunk => {
            write_chunked(upstream, raw, opts.chunk_size, opts.chunk_delay_us).await?;
        }
        BypassStrategy::SniSplit => {
            let split_at = sni_mid.clamp(1, raw.len() - 1);
            upstream.write_all(&raw[..split_at]).await?;
            upstream.flush().await?;
            if opts.chunk_delay_us > 0 {
                tokio::time::sleep(Duration::from_micros(opts.chunk_delay_us)).await;
            }
            upstream.write_all(&raw[split_at..]).await?;
            upstream.flush().await?;
        }
        BypassStrategy::TlsRecord => {
            let payload_split = sni_mid.saturating_sub(5).clamp(1, raw.len() - 6);
            if let Some((r1, r2)) = split_tls_record(raw, payload_split) {
                upstream.write_all(&r1).await?;
                upstream.flush().await?;
                if opts.chunk_delay_us > 0 {
                    tokio::time::sleep(Duration::from_micros(opts.chunk_delay_us)).await;
                }
                upstream.write_all(&r2).await?;
                upstream.flush().await?;
            } else {
                upstream.write_all(raw).await?;
                upstream.flush().await?;
            }
        }
        BypassStrategy::Combo => {
            let payload_split = sni_mid.saturating_sub(5).clamp(1, raw.len() - 6);
            if let Some((r1, r2)) = split_tls_record(raw, payload_split) {
                write_chunked(upstream, &r1, opts.chunk_size, opts.chunk_delay_us).await?;
                write_chunked(upstream, &r2, opts.chunk_size, opts.chunk_delay_us).await?;
            } else {
                write_chunked(upstream, raw, opts.chunk_size, opts.chunk_delay_us).await?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_sni_and_splits_tls_record_cleanly() {
        let rec = build_decoy_client_hello("gateway.discord.gg");
        let (start, end) = find_sni_range(&rec).expect("SNI should be found");
        assert_eq!(&rec[start..end], b"gateway.discord.gg");

        let mid_payload = (start + (end - start) / 2) - 5;
        let (r1, r2) = split_tls_record(&rec, mid_payload).expect("record split should succeed");
        assert_eq!(r1[0], 0x16);
        assert_eq!(r2[0], 0x16);
        let mut reassembled = Vec::new();
        reassembled.extend_from_slice(&r1[5..]);
        reassembled.extend_from_slice(&r2[5..]);
        assert_eq!(reassembled, &rec[5..]);
    }
}
