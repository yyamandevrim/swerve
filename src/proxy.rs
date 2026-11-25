use crate::config::{
    base_domain_for_learn, clean_domain, find_profile, BypassStrategy, Config, RoutingMode,
    BUILTIN_PROFILES,
};
use crate::dns::Resolver;
use crate::macos;
use crate::tls::{self, DesyncOptions};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::timeout;

const UI_HTML: &str = include_str!("ui.html");
const LOGO_PNG: &[u8] = include_bytes!("../assets/logo-256.png");
const LOGO_SVG: &str = include_str!("../assets/logo.svg");
const MAX_EVENTS: usize = 250;

#[derive(Clone, Serialize)]
pub struct ConnectionEvent {
    pub id: u64,
    pub timestamp_ms: u64,
    pub host: String,
    pub port: u16,
    pub action: String,
    pub strategy: Option<String>,
    pub doh: bool,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct LearnedDomain {
    pub domain: String,
    pub hits: u64,
    pub learned_at_ms: u64,
    pub last_seen_ms: u64,
}

pub struct Stats {
    pub started_at: Instant,
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub bypassed_connections: AtomicU64,
    pub auto_recovered_connections: AtomicU64,
    pub reset_connections: AtomicU64,
    pub pac_requests: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub next_event_id: AtomicU64,
    pub events: RwLock<VecDeque<ConnectionEvent>>,
    pub auto_learned: RwLock<HashMap<String, LearnedDomain>>,
    proxy_state_cache: RwLock<(Instant, bool)>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            active_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            bypassed_connections: AtomicU64::new(0),
            auto_recovered_connections: AtomicU64::new(0),
            reset_connections: AtomicU64::new(0),
            pac_requests: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            next_event_id: AtomicU64::new(1),
            events: RwLock::new(VecDeque::with_capacity(MAX_EVENTS)),
            auto_learned: RwLock::new(HashMap::new()),
            proxy_state_cache: RwLock::new((
                Instant::now()
                    .checked_sub(Duration::from_secs(60))
                    .unwrap_or_else(Instant::now),
                false,
            )),
        }
    }

    pub async fn push_event(&self, mut ev: ConnectionEvent) {
        ev.id = self.next_event_id.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.events.write().await;
        if guard.len() >= MAX_EVENTS {
            guard.pop_back();
        }
        guard.push_front(ev);
    }

    pub async fn record_auto_learned(&self, host: &str) -> String {
        let base = base_domain_for_learn(host);
        let now = now_ms();
        let mut guard = self.auto_learned.write().await;
        guard
            .entry(base.clone())
            .and_modify(|e| {
                e.hits += 1;
                e.last_seen_ms = now;
            })
            .or_insert(LearnedDomain {
                domain: base.clone(),
                hits: 1,
                learned_at_ms: now,
                last_seen_ms: now,
            });
        base
    }

    pub async fn is_auto_learned(&self, host: &str) -> bool {
        let guard = self.auto_learned.read().await;
        if guard.is_empty() {
            return false;
        }
        guard
            .keys()
            .any(|d| crate::config::domain_matches_rule(host, d))
    }

    pub async fn system_proxy_enabled(&self, listen_addr: &str) -> bool {
        {
            let cache = self.proxy_state_cache.read().await;
            if cache.0.elapsed() < Duration::from_secs(3) {
                return cache.1;
            }
        }
        let addr = listen_addr.to_string();
        let enabled = tokio::task::spawn_blocking(move || macos::is_system_proxy_enabled(&addr))
            .await
            .unwrap_or(false);
        let mut cache = self.proxy_state_cache.write().await;
        *cache = (Instant::now(), enabled);
        enabled
    }

    pub async fn set_cached_proxy_state(&self, enabled: bool) {
        let mut cache = self.proxy_state_cache.write().await;
        *cache = (Instant::now(), enabled);
    }
}

#[derive(Serialize)]
struct ProfileStatus {
    id: &'static str,
    label: &'static str,
    description: &'static str,
    domains_count: usize,
    enabled: bool,
}

#[derive(Serialize)]
struct StatusPayload {
    version: &'static str,
    pid: u32,
    uptime_secs: u64,
    listen_addr: String,
    system_proxy_enabled: bool,
    mode: RoutingMode,
    auto_learn: bool,
    strategy: BypassStrategy,
    chunk_size: usize,
    fake_count: u8,
    fake_ttl: u8,
    doh_for_matched: bool,
    profiles: Vec<ProfileStatus>,
    domains: Vec<String>,
    exclude_domains: Vec<String>,
    effective_domains_count: usize,
    auto_learned: Vec<LearnedDomain>,
    active_connections: u64,
    total_connections: u64,
    bypassed_connections: u64,
    auto_recovered_connections: u64,
    reset_connections: u64,
    pac_requests: u64,
    bytes_up: u64,
    bytes_down: u64,
    doh_queries: u64,
    doh_reused: u64,
    dns_cache_hits: u64,
    dns_cache_entries: usize,
}

#[derive(Deserialize)]
struct DomainPayload {
    domain: String,
}

#[derive(Deserialize)]
struct ProfileTogglePayload {
    id: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct ConfigUpdatePayload {
    mode: Option<RoutingMode>,
    auto_learn: Option<bool>,
    strategy: Option<BypassStrategy>,
    chunk_size: Option<usize>,
    fake_count: Option<u8>,
    fake_ttl: Option<u8>,
    doh_for_matched: Option<bool>,
}

#[derive(Deserialize)]
struct ProxyTogglePayload {
    enabled: bool,
}

#[derive(Deserialize)]
struct TestPayload {
    targets: Option<Vec<String>>,
}

#[derive(Serialize)]
struct TestResultItem {
    host: String,
    status: u16,
    ok: bool,
    latency_ms: u64,
    error: Option<String>,
}

pub struct ServerState {
    pub config: RwLock<Config>,
    pub config_path: PathBuf,
    pub resolver: Resolver,
    pub stats: Stats,
}

struct ActiveGuard(Arc<ServerState>);
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub async fn run_server(
    cfg: Config,
    config_path: PathBuf,
    auto_proxy: bool,
    verbose: bool,
) -> io::Result<()> {
    let listen_addr = cfg.listen_addr.clone();
    let listener = TcpListener::bind(&listen_addr).await?;

    let state = Arc::new(ServerState {
        config: RwLock::new(cfg.clone()),
        config_path,
        resolver: Resolver::new(),
        stats: Stats::new(),
    });

    if auto_proxy {
        match macos::enable_system_proxy(&listen_addr) {
            Ok(svcs) => eprintln!(
                "[swerve] enabled macOS system proxy ({listen_addr}) on: {}",
                svcs.join(", ")
            ),
            Err(e) => eprintln!("[swerve] warning: failed to configure macOS proxy: {e}"),
        }
    }

    eprintln!(
        "[swerve] listening on http://{listen_addr} (UI: http://{listen_addr}/ui, mode={}, strategy={}, chunk={}, auto_learn={})",
        cfg.mode, cfg.strategy, cfg.chunk_size, cfg.auto_learn
    );

    // SIGHUP hot-reload task
    let reload_state = Arc::clone(&state);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut sighup) = signal(SignalKind::hangup()) {
                while sighup.recv().await.is_some() {
                    match Config::load(&reload_state.config_path) {
                        Ok(new_cfg) => {
                            let mode = new_cfg.mode;
                            let strat = new_cfg.strategy;
                            let n = new_cfg.effective_domains().len();
                            let mut guard = reload_state.config.write().await;
                            *guard = new_cfg;
                            eprintln!(
                                "[swerve] hot-reloaded config (mode={mode}, strategy={strat}, domains={n})"
                            );
                        }
                        Err(e) => {
                            eprintln!("[swerve] failed to hot-reload config: {e}");
                        }
                    }
                }
            }
        }
    });

    // macOS network watcher: refreshes DNS cache & system proxy bypass list when Wi-Fi/Tailscale/interfaces change
    let net_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut last_fp = tokio::task::spawn_blocking(macos::network_fingerprint)
            .await
            .unwrap_or_default();
        let mut ticker = tokio::time::interval(Duration::from_secs(20));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let fp = tokio::task::spawn_blocking(macos::network_fingerprint)
                .await
                .unwrap_or_default();
            if !fp.is_empty() && fp != last_fp {
                last_fp = fp;
                let cleared = net_state.resolver.clear_cache().await;
                let listen = net_state.config.read().await.listen_addr.clone();
                let proxy_on = net_state.stats.system_proxy_enabled(&listen).await;
                if proxy_on {
                    let listen_clone = listen.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        macos::enable_system_proxy(&listen_clone)
                    })
                    .await;
                }
                eprintln!(
                    "[swerve] macOS network change detected (cleared {cleared} DNS entries, proxy_synced={proxy_on})"
                );
            }
        }
    });

    // Graceful shutdown (SIGINT / SIGTERM)
    let shutdown = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
            let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
            tokio::select! {
                _ = sigterm.recv() => {},
                _ = sigint.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    };

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                eprintln!("[swerve] shutting down...");
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        let st = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, st, verbose).await {
                                if verbose {
                                    eprintln!("[swerve] conn error: {e}");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[swerve] accept error: {e}");
                    }
                }
            }
        }
    }

    if auto_proxy {
        let _ = macos::disable_all_proxies();
        eprintln!("[swerve] disabled macOS system proxy.");
    }

    Ok(())
}

pub async fn handle_probe_connection(
    client: TcpStream,
    state: Arc<ServerState>,
) -> io::Result<()> {
    handle_client(client, state, false).await
}

fn is_likely_dpi_reset(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

async fn handle_client(
    mut client: TcpStream,
    state: Arc<ServerState>,
    verbose: bool,
) -> io::Result<()> {
    macos::tune_stream(&client);
    state.stats.active_connections.fetch_add(1, Ordering::Relaxed);
    let _guard = ActiveGuard(Arc::clone(&state));

    // Read HTTP request header (up to 16 KiB)
    let mut req_buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = timeout(Duration::from_secs(10), client.read(&mut tmp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client header timeout"))??;
        if n == 0 {
            return Ok(());
        }
        req_buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if req_buf.len() > 16384 {
            let _ = client
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    let head = String::from_utf8_lossy(&req_buf[..header_end]).to_string();
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/1.1");

    // 1. Built-in local endpoints (/ui, /logo.png, /logo.svg, /proxy.pac, /status, /api/*)
    if target.starts_with('/') {
        let content_length = parse_content_length(&head).min(65536);
        let mut body = req_buf[header_end..].to_vec();
        while body.len() < content_length {
            let mut chunk = vec![0u8; (content_length - body.len()).min(4096)];
            let n = timeout(Duration::from_secs(5), client.read(&mut chunk))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "body timeout"))??;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(content_length);

        handle_local_http(&mut client, &state, method, target, &head, &body).await?;
        return Ok(());
    }

    state.stats.total_connections.fetch_add(1, Ordering::Relaxed);

    // 2. HTTPS / WSS CONNECT tunnel
    if method.eq_ignore_ascii_case("CONNECT") {
        let t0 = Instant::now();
        let (host, port) = parse_host_port(target, 443)?;
        let cfg = state.config.read().await.clone();
        let excluded = cfg.is_excluded(&host);
        let configured_match = !excluded && cfg.matches_configured_domain(&host);
        let learned_match = !excluded
            && cfg.mode == RoutingMode::Smart
            && cfg.auto_learn
            && state.stats.is_auto_learned(&host).await;

        let should_bypass_now = !excluded
            && cfg.strategy != BypassStrategy::Skip
            && match cfg.mode {
                RoutingMode::All => true,
                RoutingMode::Smart => configured_match || learned_match,
                RoutingMode::List => configured_match,
            };

        let use_doh = should_bypass_now && cfg.doh_for_matched;

        let ips = match state.resolver.resolve(&host, use_doh, &cfg.doh_servers).await {
            Ok(ips) => ips,
            Err(e) => {
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                state
                    .stats
                    .push_event(ConnectionEvent {
                        id: 0,
                        timestamp_ms: now_ms(),
                        host,
                        port,
                        action: "error".to_string(),
                        strategy: None,
                        doh: use_doh,
                        latency_ms: t0.elapsed().as_millis() as u64,
                        error: Some(format!("dns: {e}")),
                    })
                    .await;
                return Err(e);
            }
        };

        let mut upstream = match connect_first(&ips, port, cfg.connect_timeout_ms).await {
            Ok(s) => s,
            Err(e) => {
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                state
                    .stats
                    .push_event(ConnectionEvent {
                        id: 0,
                        timestamp_ms: now_ms(),
                        host,
                        port,
                        action: "error".to_string(),
                        strategy: None,
                        doh: use_doh,
                        latency_ms: t0.elapsed().as_millis() as u64,
                        error: Some(format!("connect: {e}")),
                    })
                    .await;
                return Err(e);
            }
        };
        macos::tune_stream(&upstream);

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;

        let trailing = &req_buf[header_end..];
        let desync_opts = DesyncOptions {
            strategy: cfg.strategy,
            chunk_size: cfg.chunk_size,
            chunk_delay_us: cfg.chunk_delay_us,
            fake_count: cfg.fake_count,
            fake_ttl: cfg.fake_ttl,
        };

        let mut final_action = if should_bypass_now {
            if learned_match && !configured_match {
                "auto-bypass"
            } else {
                "bypass"
            }
        } else {
            "direct"
        };
        let mut final_doh = use_doh;

        if should_bypass_now {
            state.stats.bypassed_connections.fetch_add(1, Ordering::Relaxed);
            if learned_match && !configured_match {
                let _ = state.stats.record_auto_learned(&host).await;
            }
            if verbose {
                eprintln!("[swerve] {} ({}) -> {host}:{port}", final_action.to_uppercase(), cfg.strategy);
            }
            let hello = if !trailing.is_empty() {
                trailing.to_vec()
            } else {
                tls::read_initial_client_hello(&mut client).await?
            };
            if hello.is_empty() {
                return Ok(());
            }
            if let Err(e) = tls::send_desynced_client_hello(&mut upstream, &hello, desync_opts).await {
                state.stats.reset_connections.fetch_add(1, Ordering::Relaxed);
                state
                    .stats
                    .push_event(ConnectionEvent {
                        id: 0,
                        timestamp_ms: now_ms(),
                        host,
                        port,
                        action: "reset".to_string(),
                        strategy: Some(cfg.strategy.to_string()),
                        doh: use_doh,
                        latency_ms: t0.elapsed().as_millis() as u64,
                        error: Some(e.to_string()),
                    })
                    .await;
                return Err(e);
            }
        } else if !excluded
            && cfg.mode == RoutingMode::Smart
            && cfg.auto_learn
            && cfg.strategy != BypassStrategy::Skip
            && port == 443
        {
            // Zero-error Auto-Learn probe:
            // Buffer the ClientHello, try direct first, and if the ISP immediately resets the TLS handshake,
            // transparently reconnect via DoH + DPI bypass on this exact same client socket!
            let hello = if !trailing.is_empty() {
                trailing.to_vec()
            } else {
                tls::read_initial_client_hello(&mut client).await?
            };
            if hello.is_empty() {
                return Ok(());
            }

            let is_tls_hello = hello.len() >= 6 && hello[0] == 0x16 && hello[1] == 0x03;
            let mut need_recovery = false;

            if upstream.write_all(&hello).await.is_err() || upstream.flush().await.is_err() {
                need_recovery = is_tls_hello;
            } else if is_tls_hello {
                let mut first_resp = [0u8; 4096];
                match timeout(Duration::from_secs(3), upstream.read(&mut first_resp)).await {
                    Ok(Ok(n @ 1..)) => {
                        client.write_all(&first_resp[..n]).await?;
                        client.flush().await?;
                    }
                    Ok(Ok(0)) => {
                        need_recovery = true;
                    }
                    Ok(Err(e)) if is_likely_dpi_reset(&e) => {
                        need_recovery = true;
                    }
                    Ok(Err(e)) => {
                        return Err(e);
                    }
                    Err(_) => {
                        // Slow server, not a reset — proceed normally without interfering
                    }
                }
            }

            if need_recovery {
                drop(upstream);
                let doh_ips = state
                    .resolver
                    .resolve(&host, cfg.doh_for_matched, &cfg.doh_servers)
                    .await?;
                let mut retry_upstream =
                    connect_first(&doh_ips, port, cfg.connect_timeout_ms).await?;
                macos::tune_stream(&retry_upstream);

                tls::send_desynced_client_hello(&mut retry_upstream, &hello, desync_opts).await?;

                let mut verify_buf = [0u8; 4096];
                match timeout(Duration::from_secs(4), retry_upstream.read(&mut verify_buf)).await {
                    Ok(Ok(n @ 1..)) => {
                        let learned = state.stats.record_auto_learned(&host).await;
                        state.stats.bypassed_connections.fetch_add(1, Ordering::Relaxed);
                        state
                            .stats
                            .auto_recovered_connections
                            .fetch_add(1, Ordering::Relaxed);
                        final_action = "auto-bypass";
                        final_doh = cfg.doh_for_matched;
                        eprintln!(
                            "[swerve] auto-learned DPI block on {host} -> added {learned} (seamless recovery)"
                        );
                        client.write_all(&verify_buf[..n]).await?;
                        client.flush().await?;
                        upstream = retry_upstream;
                    }
                    other => {
                        state.stats.reset_connections.fetch_add(1, Ordering::Relaxed);
                        let err_msg = match other {
                            Ok(Err(e)) => e.to_string(),
                            Ok(Ok(_)) => "upstream closed after bypass retry".to_string(),
                            Err(_) => "timeout after bypass retry".to_string(),
                        };
                        state
                            .stats
                            .push_event(ConnectionEvent {
                                id: 0,
                                timestamp_ms: now_ms(),
                                host,
                                port,
                                action: "reset".to_string(),
                                strategy: Some(cfg.strategy.to_string()),
                                doh: cfg.doh_for_matched,
                                latency_ms: t0.elapsed().as_millis() as u64,
                                error: Some(err_msg.clone()),
                            })
                            .await;
                        return Err(io::Error::new(io::ErrorKind::ConnectionReset, err_msg));
                    }
                }
            }
        } else {
            if verbose {
                eprintln!("[swerve] DIRECT -> {host}:{port}");
            }
            if !trailing.is_empty() {
                upstream.write_all(trailing).await?;
            }
        }

        let setup_ms = t0.elapsed().as_millis() as u64;
        state
            .stats
            .push_event(ConnectionEvent {
                id: 0,
                timestamp_ms: now_ms(),
                host: host.clone(),
                port,
                action: final_action.to_string(),
                strategy: if final_action != "direct" {
                    Some(cfg.strategy.to_string())
                } else {
                    None
                },
                doh: final_doh,
                latency_ms: setup_ms,
                error: None,
            })
            .await;

        match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
            Ok((up, down)) => {
                state.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                state.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::ConnectionReset
                    && t0.elapsed() < Duration::from_secs(3)
                {
                    state.stats.reset_connections.fetch_add(1, Ordering::Relaxed);
                    state
                        .stats
                        .push_event(ConnectionEvent {
                            id: 0,
                            timestamp_ms: now_ms(),
                            host,
                            port,
                            action: "reset".to_string(),
                            strategy: if final_action != "direct" {
                                Some(cfg.strategy.to_string())
                            } else {
                                None
                            },
                            doh: final_doh,
                            latency_ms: t0.elapsed().as_millis() as u64,
                            error: Some("connection reset (possible DPI)".to_string()),
                        })
                        .await;
                }
            }
        }
        return Ok(());
    }

    // 3. Plain HTTP proxy request
    if let Some(rest) = target.strip_prefix("http://") {
        let t0 = Instant::now();
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        let (host, port) = parse_host_port(authority, 80)?;
        let cfg = state.config.read().await.clone();
        let excluded = cfg.is_excluded(&host);
        let matched = !excluded
            && (cfg.mode == RoutingMode::All
                || cfg.matches_configured_domain(&host)
                || (cfg.mode == RoutingMode::Smart
                    && cfg.auto_learn
                    && state.stats.is_auto_learned(&host).await));
        let use_doh = matched && cfg.doh_for_matched;
        let ips = state
            .resolver
            .resolve(&host, use_doh, &cfg.doh_servers)
            .await?;
        let mut upstream = connect_first(&ips, port, cfg.connect_timeout_ms).await?;
        macos::tune_stream(&upstream);

        let mut rebuilt = format!("{method} {path} {version}\r\n");
        for line in head.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            if line.to_ascii_lowercase().starts_with("proxy-connection:") {
                continue;
            }
            if matched && line.to_ascii_lowercase().starts_with("host:") {
                rebuilt.push_str("hOsT:");
                rebuilt.push_str(&line[5..]);
                rebuilt.push_str("\r\n");
            } else {
                rebuilt.push_str(line);
                rebuilt.push_str("\r\n");
            }
        }
        rebuilt.push_str("\r\n");

        if matched {
            state.stats.bypassed_connections.fetch_add(1, Ordering::Relaxed);
            let bytes = rebuilt.as_bytes();
            let mid = (bytes.len() / 2).max(1);
            upstream.write_all(&bytes[..mid]).await?;
            upstream.flush().await?;
            upstream.write_all(&bytes[mid..]).await?;
        } else {
            upstream.write_all(rebuilt.as_bytes()).await?;
        }

        if header_end < req_buf.len() {
            upstream.write_all(&req_buf[header_end..]).await?;
        }
        upstream.flush().await?;

        state
            .stats
            .push_event(ConnectionEvent {
                id: 0,
                timestamp_ms: now_ms(),
                host,
                port,
                action: if matched { "bypass" } else { "direct" }.to_string(),
                strategy: if matched { Some("http-split".to_string()) } else { None },
                doh: use_doh,
                latency_ms: t0.elapsed().as_millis() as u64,
                error: None,
            })
            .await;

        if let Ok((up, down)) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
            state.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
            state.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
        }
        return Ok(());
    }

    client
        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    Ok(())
}

async fn handle_local_http(
    client: &mut TcpStream,
    state: &Arc<ServerState>,
    method: &str,
    target: &str,
    headers: &str,
    body: &[u8],
) -> io::Result<()> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    if !method.eq_ignore_ascii_case("GET") && !is_local_origin(headers) {
        write_json(client, "403 Forbidden", r#"{"error":"forbidden origin"}"#).await?;
        return Ok(());
    }

    match (method, path) {
        ("GET", "/") => {
            client
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: /ui\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
        }
        ("GET", "/ui") | ("GET", "/ui/") => {
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{}",
                UI_HTML.len(),
                UI_HTML
            );
            client.write_all(resp.as_bytes()).await?;
        }
        ("GET", "/logo.png") => {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nCache-Control: public, max-age=86400\r\nConnection: close\r\n\r\n",
                LOGO_PNG.len()
            );
            client.write_all(header.as_bytes()).await?;
            client.write_all(LOGO_PNG).await?;
        }
        ("GET", "/logo.svg") | ("GET", "/favicon.svg") => {
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: {}\r\nCache-Control: public, max-age=86400\r\nConnection: close\r\n\r\n{}",
                LOGO_SVG.len(),
                LOGO_SVG
            );
            client.write_all(resp.as_bytes()).await?;
        }
        ("GET", "/proxy.pac") | ("GET", "/pac") => {
            state.stats.pac_requests.fetch_add(1, Ordering::Relaxed);
            let pac = state.config.read().await.generate_pac();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{}",
                pac.len(),
                pac
            );
            client.write_all(resp.as_bytes()).await?;
        }
        ("GET", "/status") | ("GET", "/health") | ("GET", "/api/status") => {
            let cfg = state.config.read().await.clone();
            let proxy_on = state.stats.system_proxy_enabled(&cfg.listen_addr).await;
            let profiles: Vec<ProfileStatus> = BUILTIN_PROFILES
                .iter()
                .map(|p| ProfileStatus {
                    id: p.id,
                    label: p.label,
                    description: p.description,
                    domains_count: p.domains.len(),
                    enabled: cfg.profiles.iter().any(|x| x.eq_ignore_ascii_case(p.id)),
                })
                .collect();

            let mut learned: Vec<LearnedDomain> = state
                .stats
                .auto_learned
                .read()
                .await
                .values()
                .cloned()
                .collect();
            learned.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));

            let effective_domains_count = cfg.effective_domains().len();
            let payload = StatusPayload {
                version: env!("CARGO_PKG_VERSION"),
                pid: std::process::id(),
                uptime_secs: state.stats.started_at.elapsed().as_secs(),
                listen_addr: cfg.listen_addr,
                system_proxy_enabled: proxy_on,
                mode: cfg.mode,
                auto_learn: cfg.auto_learn,
                strategy: cfg.strategy,
                chunk_size: cfg.chunk_size,
                fake_count: cfg.fake_count,
                fake_ttl: cfg.fake_ttl,
                doh_for_matched: cfg.doh_for_matched,
                profiles,
                domains: cfg.domains,
                exclude_domains: cfg.exclude_domains,
                effective_domains_count,
                auto_learned: learned,
                active_connections: state.stats.active_connections.load(Ordering::Relaxed),
                total_connections: state.stats.total_connections.load(Ordering::Relaxed),
                bypassed_connections: state.stats.bypassed_connections.load(Ordering::Relaxed),
                auto_recovered_connections: state
                    .stats
                    .auto_recovered_connections
                    .load(Ordering::Relaxed),
                reset_connections: state.stats.reset_connections.load(Ordering::Relaxed),
                pac_requests: state.stats.pac_requests.load(Ordering::Relaxed),
                bytes_up: state.stats.bytes_up.load(Ordering::Relaxed),
                bytes_down: state.stats.bytes_down.load(Ordering::Relaxed),
                doh_queries: state.resolver.doh_queries.load(Ordering::Relaxed),
                doh_reused: state.resolver.doh_reused.load(Ordering::Relaxed),
                dns_cache_hits: state.resolver.cache_hits.load(Ordering::Relaxed),
                dns_cache_entries: state.resolver.cache_len().await,
            };
            let json = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
            write_json(client, "200 OK", &json).await?;
        }
        ("GET", "/api/events") => {
            let limit = parse_query_usize(query, "limit").unwrap_or(120).min(MAX_EVENTS);
            let guard = state.stats.events.read().await;
            let list: Vec<&ConnectionEvent> = guard.iter().take(limit).collect();
            let json = serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string());
            write_json(client, "200 OK", &json).await?;
        }
        ("POST", "/api/profiles") => match serde_json::from_slice::<ProfileTogglePayload>(body) {
            Ok(p) => {
                if find_profile(&p.id).is_none() {
                    write_json(client, "400 Bad Request", r#"{"error":"unknown profile"}"#).await?;
                } else {
                    let mut cfg = state.config.write().await;
                    let id_low = p.id.to_ascii_lowercase();
                    if p.enabled {
                        if !cfg.profiles.iter().any(|x| x.eq_ignore_ascii_case(&id_low)) {
                            cfg.profiles.push(id_low.clone());
                        }
                    } else {
                        cfg.profiles.retain(|x| !x.eq_ignore_ascii_case(&id_low));
                    }
                    let _ = cfg.save(&state.config_path);
                    let resp = serde_json::json!({ "ok": true, "id": id_low, "enabled": p.enabled }).to_string();
                    write_json(client, "200 OK", &resp).await?;
                }
            }
            Err(_) => {
                write_json(client, "400 Bad Request", r#"{"error":"invalid JSON"}"#).await?;
            }
        },
        ("POST", "/api/domains") => match serde_json::from_slice::<DomainPayload>(body) {
            Ok(p) => {
                let clean = clean_domain(&p.domain);
                if clean.is_empty() || !clean.contains('.') {
                    write_json(client, "400 Bad Request", r#"{"error":"invalid domain"}"#).await?;
                } else {
                    {
                        let mut cfg = state.config.write().await;
                        cfg.exclude_domains.retain(|d| !d.eq_ignore_ascii_case(&clean));
                        if !cfg.domains.iter().any(|d| d.eq_ignore_ascii_case(&clean)) {
                            cfg.domains.push(clean.clone());
                        }
                        let _ = cfg.save(&state.config_path);
                    }
                    state.stats.auto_learned.write().await.remove(&clean);
                    let resp = serde_json::json!({ "ok": true, "domain": clean }).to_string();
                    write_json(client, "200 OK", &resp).await?;
                }
            }
            Err(_) => {
                write_json(client, "400 Bad Request", r#"{"error":"invalid JSON"}"#).await?;
            }
        },
        ("DELETE", "/api/domains") => match serde_json::from_slice::<DomainPayload>(body) {
            Ok(p) => {
                let clean = clean_domain(&p.domain);
                let mut cfg = state.config.write().await;
                cfg.domains.retain(|d| !d.eq_ignore_ascii_case(&clean));
                let _ = cfg.save(&state.config_path);
                let resp = serde_json::json!({ "ok": true, "domain": clean }).to_string();
                write_json(client, "200 OK", &resp).await?;
            }
            Err(_) => {
                write_json(client, "400 Bad Request", r#"{"error":"invalid JSON"}"#).await?;
            }
        },
        ("POST", "/api/exclude") => match serde_json::from_slice::<DomainPayload>(body) {
            Ok(p) => {
                let clean = clean_domain(&p.domain);
                if clean.is_empty() || !clean.contains('.') {
                    write_json(client, "400 Bad Request", r#"{"error":"invalid domain"}"#).await?;
                } else {
                    {
                        let mut cfg = state.config.write().await;
                        cfg.domains.retain(|d| !d.eq_ignore_ascii_case(&clean));
                        if !cfg.exclude_domains.iter().any(|d| d.eq_ignore_ascii_case(&clean)) {
                            cfg.exclude_domains.push(clean.clone());
                        }
                        let _ = cfg.save(&state.config_path);
                    }
                    state.stats.auto_learned.write().await.remove(&clean);
                    let resp = serde_json::json!({ "ok": true, "domain": clean }).to_string();
                    write_json(client, "200 OK", &resp).await?;
                }
            }
            Err(_) => {
                write_json(client, "400 Bad Request", r#"{"error":"invalid JSON"}"#).await?;
            }
        },
        ("DELETE", "/api/exclude") => match serde_json::from_slice::<DomainPayload>(body) {
            Ok(p) => {
                let clean = clean_domain(&p.domain);
                let mut cfg = state.config.write().await;
                cfg.exclude_domains.retain(|d| !d.eq_ignore_ascii_case(&clean));
                let _ = cfg.save(&state.config_path);
                let resp = serde_json::json!({ "ok": true, "domain": clean }).to_string();
                write_json(client, "200 OK", &resp).await?;
            }
            Err(_) => {
                write_json(client, "400 Bad Request", r#"{"error":"invalid JSON"}"#).await?;
            }
        },
        ("DELETE", "/api/learned") => match serde_json::from_slice::<DomainPayload>(body) {
            Ok(p) => {
                let clean = clean_domain(&p.domain);
                state.stats.auto_learned.write().await.remove(&clean);
                let resp = serde_json::json!({ "ok": true, "domain": clean }).to_string();
                write_json(client, "200 OK", &resp).await?;
            }
            Err(_) => {
                state.stats.auto_learned.write().await.clear();
                write_json(client, "200 OK", r#"{"ok":true,"cleared":true}"#).await?;
            }
        },
        ("POST", "/api/dns/clear") => {
            let cleared = state.resolver.clear_cache().await;
            let resp = serde_json::json!({ "ok": true, "cleared": cleared }).to_string();
            write_json(client, "200 OK", &resp).await?;
        }
        ("POST", "/api/config") => match serde_json::from_slice::<ConfigUpdatePayload>(body) {
            Ok(p) => {
                let mut cfg = state.config.write().await;
                if let Some(m) = p.mode {
                    cfg.mode = m;
                }
                if let Some(a) = p.auto_learn {
                    cfg.auto_learn = a;
                }
                if let Some(s) = p.strategy {
                    cfg.strategy = s;
                }
                if let Some(c) = p.chunk_size {
                    cfg.chunk_size = c.clamp(1, 64);
                }
                if let Some(fc) = p.fake_count {
                    cfg.fake_count = fc.min(5);
                }
                if let Some(ft) = p.fake_ttl {
                    cfg.fake_ttl = ft.clamp(1, 32);
                }
                if let Some(d) = p.doh_for_matched {
                    cfg.doh_for_matched = d;
                }
                let _ = cfg.save(&state.config_path);
                let resp = serde_json::json!({
                    "ok": true,
                    "mode": cfg.mode,
                    "auto_learn": cfg.auto_learn,
                    "strategy": cfg.strategy,
                    "chunk_size": cfg.chunk_size,
                    "fake_count": cfg.fake_count,
                    "fake_ttl": cfg.fake_ttl,
                    "doh_for_matched": cfg.doh_for_matched
                })
                .to_string();
                write_json(client, "200 OK", &resp).await?;
            }
            Err(_) => {
                write_json(client, "400 Bad Request", r#"{"error":"invalid JSON"}"#).await?;
            }
        },
        ("POST", "/api/proxy/toggle") => match serde_json::from_slice::<ProxyTogglePayload>(body) {
            Ok(p) => {
                let listen = state.config.read().await.listen_addr.clone();
                let target_on = p.enabled;
                let res = tokio::task::spawn_blocking(move || {
                    if target_on {
                        macos::enable_system_proxy(&listen)
                    } else {
                        macos::disable_all_proxies()
                    }
                })
                .await;
                match res {
                    Ok(Ok(svcs)) => {
                        state.stats.set_cached_proxy_state(target_on).await;
                        let resp = serde_json::json!({
                            "ok": true,
                            "enabled": target_on,
                            "services": svcs
                        })
                        .to_string();
                        write_json(client, "200 OK", &resp).await?;
                    }
                    _ => {
                        write_json(
                            client,
                            "500 Internal Server Error",
                            r#"{"error":"failed to update macOS proxy"}"#,
                        )
                        .await?;
                    }
                }
            }
            Err(_) => {
                write_json(client, "400 Bad Request", r#"{"error":"invalid JSON"}"#).await?;
            }
        },
        ("POST", "/api/test") => {
            let listen = state.config.read().await.listen_addr.clone();
            let custom_targets = serde_json::from_slice::<TestPayload>(body)
                .ok()
                .and_then(|p| p.targets)
                .filter(|v| !v.is_empty());
            let results = run_connectivity_probe(&listen, custom_targets).await;
            let resp = serde_json::json!({ "results": results }).to_string();
            write_json(client, "200 OK", &resp).await?;
        }
        _ => {
            client
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
        }
    }
    Ok(())
}

async fn write_json(client: &mut TcpStream, status: &str, json: &str) -> io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{}",
        json.len(),
        json
    );
    client.write_all(resp.as_bytes()).await
}

fn parse_content_length(headers: &str) -> usize {
    for line in headers.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }
    0
}

fn is_local_origin(headers: &str) -> bool {
    let mut host_ok = false;
    let mut origin_ok = true;
    for line in headers.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim().to_ascii_lowercase();
            if key.eq_ignore_ascii_case("host") {
                host_ok = val.starts_with("127.0.0.1") || val.starts_with("localhost");
            } else if key.eq_ignore_ascii_case("origin") {
                origin_ok =
                    val.starts_with("http://127.0.0.1") || val.starts_with("http://localhost");
            }
        }
    }
    host_ok && origin_ok
}

fn parse_query_usize(query: &str, key: &str) -> Option<usize> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return v.parse::<usize>().ok();
            }
        }
    }
    None
}

async fn run_connectivity_probe(
    listen_addr: &str,
    custom_targets: Option<Vec<String>>,
) -> Vec<TestResultItem> {
    let targets: Vec<String> = custom_targets.unwrap_or_else(|| {
        [
            "discord.com",
            "gateway.discord.gg",
            "cdn.discordapp.com",
            "pastebin.com",
            "roblox.com",
            "example.com",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    });

    let mut handles = Vec::new();
    for raw in targets {
        let h = clean_domain(&raw);
        if h.is_empty() {
            continue;
        }
        let proxy = format!("http://{listen_addr}");
        handles.push(tokio::task::spawn_blocking(move || {
            let t0 = Instant::now();
            let url = format!("https://{h}");
            let out = std::process::Command::new("curl")
                .args([
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "-m",
                    "6",
                    "-x",
                    &proxy,
                    &url,
                ])
                .output();
            let latency_ms = t0.elapsed().as_millis() as u64;
            match out {
                Ok(o) => {
                    let code = String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .parse::<u16>()
                        .unwrap_or(0);
                    let ok = code >= 200 && code < 500;
                    TestResultItem {
                        host: h,
                        status: code,
                        ok,
                        latency_ms,
                        error: if ok {
                            None
                        } else {
                            Some("blocked/reset".to_string())
                        },
                    }
                }
                Err(e) => TestResultItem {
                    host: h,
                    status: 0,
                    ok: false,
                    latency_ms,
                    error: Some(e.to_string()),
                },
            }
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(item) = h.await {
            results.push(item);
        }
    }
    results
}

fn parse_host_port(target: &str, default_port: u16) -> io::Result<(String, u16)> {
    if let Some(stripped) = target.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv6 host"))?;
        let host = stripped[..end].to_string();
        let rest = &stripped[end + 1..];
        let port = if let Some(p) = rest.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"))?
        } else {
            default_port
        };
        return Ok((host, port));
    }

    match target.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => {
            let port = p
                .parse::<u16>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"))?;
            Ok((h.to_string(), port))
        }
        _ => Ok((target.to_string(), default_port)),
    }
}

async fn connect_first(
    ips: &[std::net::IpAddr],
    port: u16,
    timeout_ms: u64,
) -> io::Result<TcpStream> {
    let mut last_err = None;
    let per_try = Duration::from_millis(timeout_ms.clamp(1000, 30000));
    for ip in ips.iter().take(3) {
        let addr = SocketAddr::new(*ip, port);
        match timeout(per_try, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect timeout to {addr}"),
                ))
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "connect failed")))
}
