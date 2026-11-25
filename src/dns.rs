use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

struct CacheEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

struct PooledDohConn {
    server: String,
    stream: TlsStream<TcpStream>,
    last_used: Instant,
}

pub struct Resolver {
    tls: TlsConnector,
    cache: RwLock<HashMap<String, CacheEntry>>,
    doh_pool: Mutex<Option<PooledDohConn>>,
    pub cache_hits: AtomicU64,
    pub doh_queries: AtomicU64,
    pub doh_reused: AtomicU64,
}

impl Resolver {
    pub fn new() -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            tls: TlsConnector::from(Arc::new(config)),
            cache: RwLock::new(HashMap::new()),
            doh_pool: Mutex::new(None),
            cache_hits: AtomicU64::new(0),
            doh_queries: AtomicU64::new(0),
            doh_reused: AtomicU64::new(0),
        }
    }

    pub async fn cache_len(&self) -> usize {
        self.cache.read().await.len()
    }

    pub async fn clear_cache(&self) -> usize {
        let mut guard = self.cache.write().await;
        let len = guard.len();
        guard.clear();
        // Also drop any pooled DoH socket (useful after network change / wake from sleep)
        let mut pool = self.doh_pool.lock().await;
        *pool = None;
        len
    }

    pub async fn resolve(
        &self,
        host: &str,
        use_doh: bool,
        doh_servers: &[String],
    ) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let key = format!(
            "{}:{}",
            if use_doh { "doh" } else { "sys" },
            host.to_ascii_lowercase()
        );
        {
            let guard = self.cache.read().await;
            if let Some(entry) = guard.get(&key) {
                if Instant::now() < entry.expires_at && !entry.ips.is_empty() {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(entry.ips.clone());
                }
            }
        }

        let (ips, ttl) = if use_doh {
            self.doh_queries.fetch_add(1, Ordering::Relaxed);
            match self.resolve_doh(host, doh_servers).await {
                Ok(res) => res,
                Err(_) => self.resolve_system(host).await?,
            }
        } else {
            self.resolve_system(host).await?
        };

        if !ips.is_empty() {
            let mut guard = self.cache.write().await;
            if guard.len() > 4096 {
                let now = Instant::now();
                guard.retain(|_, v| v.expires_at > now);
            }
            guard.insert(
                key,
                CacheEntry {
                    ips: ips.clone(),
                    expires_at: Instant::now() + Duration::from_secs(ttl.clamp(30, 3600)),
                },
            );
        }

        Ok(ips)
    }

    async fn resolve_system(&self, host: &str) -> io::Result<(Vec<IpAddr>, u64)> {
        let addrs = tokio::net::lookup_host((host, 443)).await?;
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for addr in addrs {
            match addr.ip() {
                IpAddr::V4(ip) => {
                    if !v4.contains(&IpAddr::V4(ip)) {
                        v4.push(IpAddr::V4(ip));
                    }
                }
                IpAddr::V6(ip) => {
                    if !v6.contains(&IpAddr::V6(ip)) {
                        v6.push(IpAddr::V6(ip));
                    }
                }
            }
        }
        v4.extend(v6);
        if v4.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no addresses resolved for {host}"),
            ));
        }
        Ok((v4, 60))
    }

    async fn resolve_doh(
        &self,
        host: &str,
        doh_servers: &[String],
    ) -> io::Result<(Vec<IpAddr>, u64)> {
        let query = encode_dns_query(host, 1)?; // Type A
        let servers: Vec<&str> = if doh_servers.is_empty() {
            vec!["1.1.1.1", "1.0.0.1", "8.8.8.8"]
        } else {
            doh_servers.iter().map(|s| s.as_str()).collect()
        };

        let mut last_err = None;
        for srv in servers {
            match timeout(Duration::from_secs(4), self.doh_post_keepalive(srv, &query)).await {
                Ok(Ok(body)) => {
                    let (ips, ttl) = decode_dns_a_response(&body)?;
                    if !ips.is_empty() {
                        return Ok((ips, ttl));
                    }
                    last_err = Some(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("DoH {srv} returned no A records for {host}"),
                    ));
                }
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => {
                    last_err = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("DoH {srv} timed out"),
                    ))
                }
            }
        }

        Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "DoH failed")))
    }

    /// Uses a persistent HTTP/1.1 keep-alive TLS connection to the DoH resolver,
    /// transparently reconnecting if the pooled connection was closed or idle too long.
    async fn doh_post_keepalive(&self, server_ip_str: &str, dns_msg: &[u8]) -> io::Result<Vec<u8>> {
        // 1. Try taking a warm pooled connection for this server
        let warm = {
            let mut pool = self.doh_pool.lock().await;
            match pool.take() {
                Some(c) if c.server == server_ip_str && c.last_used.elapsed() < Duration::from_secs(45) => Some(c),
                _ => None,
            }
        };

        if let Some(mut conn) = warm {
            match send_doh_http11(&mut conn.stream, server_ip_str, dns_msg).await {
                Ok((body, keep_alive)) => {
                    self.doh_reused.fetch_add(1, Ordering::Relaxed);
                    if keep_alive {
                        conn.last_used = Instant::now();
                        let mut pool = self.doh_pool.lock().await;
                        *pool = Some(conn);
                    }
                    return Ok(body);
                }
                Err(_) => {
                    // Warm socket was stale/reset; fall through to open a fresh connection
                }
            }
        }

        // 2. Open fresh TLS connection directly to DoH server IP
        let ip: IpAddr = server_ip_str.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DoH IP {server_ip_str}: {e}"),
            )
        })?;
        let tcp = TcpStream::connect(SocketAddr::new(ip, 443)).await?;
        let _ = tcp.set_nodelay(true);

        let mut stream = self
            .tls
            .connect(ServerName::from(ip), tcp)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("DoH TLS error: {e}")))?;

        let (body, keep_alive) = send_doh_http11(&mut stream, server_ip_str, dns_msg).await?;
        if keep_alive {
            let mut pool = self.doh_pool.lock().await;
            *pool = Some(PooledDohConn {
                server: server_ip_str.to_string(),
                stream,
                last_used: Instant::now(),
            });
        }
        Ok(body)
    }
}

async fn send_doh_http11(
    stream: &mut TlsStream<TcpStream>,
    server_ip_str: &str,
    dns_msg: &[u8],
) -> io::Result<(Vec<u8>, bool)> {
    let req = format!(
        "POST /dns-query HTTP/1.1\r\nHost: {server_ip_str}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        dns_msg.len()
    );
    stream.write_all(req.as_bytes()).await?;
    stream.write_all(dns_msg).await?;
    stream.flush().await?;

    // Read headers until \r\n\r\n
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoH connection closed"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 16384 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DoH headers too large"));
        }
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let status_line = headers.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("DoH non-200 status: {status_line}"),
        ));
    }

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut server_close = false;
    for line in headers.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let k_low = k.trim().to_ascii_lowercase();
            let v_low = v.trim().to_ascii_lowercase();
            if k_low == "content-length" {
                content_length = v_low.parse::<usize>().ok();
            } else if k_low == "transfer-encoding" && v_low.contains("chunked") {
                chunked = true;
            } else if k_low == "connection" && v_low.contains("close") {
                server_close = true;
            }
        }
    }

    let mut body = buf[header_end..].to_vec();
    if let Some(len) = content_length {
        while body.len() < len {
            let need = (len - body.len()).min(4096);
            let mut chunk = vec![0u8; need];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoH truncated body"));
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(len);
        Ok((body, !server_close))
    } else if chunked {
        loop {
            if let Ok((decoded, done)) = try_decode_chunked(&body) {
                if done {
                    return Ok((decoded, !server_close));
                }
            }
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoH truncated chunked body"));
            }
            body.extend_from_slice(&tmp[..n]);
        }
    } else {
        stream.read_to_end(&mut body).await?;
        Ok((body, false))
    }
}

fn try_decode_chunked(mut data: &[u8]) -> io::Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    loop {
        let Some(crlf) = data.windows(2).position(|w| w == b"\r\n") else {
            return Ok((out, false));
        };
        let size_str = std::str::from_utf8(&data[..crlf])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 chunk size"))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hex chunk size"))?;
        data = &data[crlf + 2..];
        if size == 0 {
            if data.len() >= 2 && &data[..2] == b"\r\n" {
                return Ok((out, true));
            }
            return Ok((out, false));
        }
        if data.len() < size + 2 {
            return Ok((out, false));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// Encodes a standard RFC 1035 DNS query packet (RD=1, 1 question).
pub fn encode_dns_query(domain: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid domain label"));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    Ok(buf)
}

fn skip_dns_name(buf: &[u8], mut offset: usize) -> io::Result<usize> {
    let mut jumps = 0;
    loop {
        if offset >= buf.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated DNS name"));
        }
        let len = buf[offset];
        if len == 0 {
            return Ok(offset + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= buf.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated DNS ptr"));
            }
            return Ok(offset + 2);
        }
        offset += 1 + (len as usize);
        jumps += 1;
        if jumps > 128 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS name loop"));
        }
    }
}

/// Decodes A (IPv4) answers and minimum TTL from an RFC 1035 DNS wire-format response.
pub fn decode_dns_a_response(buf: &[u8]) -> io::Result<(Vec<IpAddr>, u64)> {
    if buf.len() < 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS response too short"));
    }
    let rcode = buf[3] & 0x0F;
    if rcode != 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("DNS RCODE {rcode}")));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(buf, offset)?;
        if offset + 4 > buf.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated question"));
        }
        offset += 4;
    }

    let mut ips = Vec::new();
    let mut min_ttl: u64 = 300;
    for _ in 0..ancount {
        offset = skip_dns_name(buf, offset)?;
        if offset + 10 > buf.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated answer"));
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]) as u64;
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlen > buf.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated rdata"));
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            let ip = IpAddr::V4(Ipv4Addr::new(
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ));
            ips.push(ip);
            if ttl > 0 && ttl < min_ttl {
                min_ttl = ttl;
            }
        }
        offset += rdlen;
    }

    Ok((ips, min_ttl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_valid_query() {
        let q = encode_dns_query("discord.com", 1).unwrap();
        assert_eq!(&q[12..25], b"\x07discord\x03com\x00");
        assert_eq!(&q[25..29], &[0x00, 0x01, 0x00, 0x01]);
    }
}
