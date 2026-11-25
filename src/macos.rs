use socket2::{SockRef, TcpKeepalive};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tokio::net::TcpStream;

pub const LAUNCHD_LABEL: &str = "dev.swerve.agent";

/// Apply macOS/XNU-specific socket options:
/// - `TCP_NODELAY`: flush small ClientHello fragments immediately without Nagle coalescing
/// - `SO_NOSIGPIPE`: prevent SIGPIPE when an ISP DPI box injects TCP RST mid-write
/// - `TCP_KEEPALIVE`: detect stale WebSocket tunnels after sleep or Wi-Fi/Tailscale switches
pub fn tune_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);

    #[cfg(target_os = "macos")]
    unsafe {
        let fd = stream.as_raw_fd();
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let sock = SockRef::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10));
    let _ = sock.set_tcp_keepalive(&keepalive);
}

/// Lists enabled macOS network services suitable for proxy configuration,
/// including VPN services like Tailscale (which otherwise shadow Wi-Fi's proxy settings).
pub fn list_network_services() -> io::Result<Vec<String>> {
    let out = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            String::from_utf8_lossy(&out.stderr).to_string(),
        ));
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut services = Vec::new();
    for line in text.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with("An asterisk") || s.starts_with('*') {
            continue;
        }
        if s.eq_ignore_ascii_case("Thunderbolt Bridge") {
            continue;
        }
        services.push(s.to_string());
    }
    Ok(services)
}

/// Collects local & Tailscale/VPN search domains from `scutil --dns` so local/VPN traffic bypasses the proxy.
pub fn discover_bypass_domains() -> Vec<String> {
    let mut domains: BTreeSet<String> = [
        "localhost",
        "127.0.0.1",
        "::1",
        "*.local",
        "169.254/16",
        "10.0.0.0/8",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "*.ts.net",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    if let Ok(out) = Command::new("scutil").arg("--dns").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some((_, val)) = trimmed.split_once(':') {
                if trimmed.starts_with("search domain") || trimmed.starts_with("domain") {
                    let dom = val.trim().trim_end_matches('.');
                    if !dom.is_empty()
                        && !dom.contains("placeholder-")
                        && !dom.ends_with(".arpa")
                        && dom.contains('.')
                    {
                        domains.insert(format!("*.{dom}"));
                    }
                }
            }
        }
    }

    domains.into_iter().collect()
}

/// Lightweight network state fingerprint used by the background watcher to detect
/// Wi-Fi/Ethernet/Tailscale changes and auto-refresh proxy bypass lists + DNS cache.
pub fn network_fingerprint() -> String {
    let svcs = list_network_services().unwrap_or_default().join(",");
    let bypass = discover_bypass_domains().join(",");
    let nwi = Command::new("scutil")
        .arg("--nwi")
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| l.contains("address") || l.contains("Network interfaces:"))
                .collect::<Vec<_>>()
                .join("|")
        })
        .unwrap_or_default();
    format!("{svcs}##{bypass}##{nwi}")
}

/// Enables macOS system HTTP + HTTPS proxy on all active network services (including Tailscale)
/// with bypass domains for localhost, LAN, and Tailscale MagicDNS.
pub fn enable_system_proxy(listen_addr: &str) -> io::Result<Vec<String>> {
    let (host, port) = listen_addr.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid listen_addr: {listen_addr}"),
        )
    })?;

    let services = list_network_services()?;
    let bypass = discover_bypass_domains();
    let mut configured = Vec::new();

    for svc in &services {
        let _ = Command::new("networksetup")
            .args(["-setautoproxystate", svc, "off"])
            .status();

        let web_ok = Command::new("networksetup")
            .args(["-setwebproxy", svc, host, port])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        let sec_ok = Command::new("networksetup")
            .args(["-setsecurewebproxy", svc, host, port])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        let mut bypass_args = vec!["-setproxybypassdomains".to_string(), svc.clone()];
        bypass_args.extend(bypass.iter().cloned());
        let _ = Command::new("networksetup").args(&bypass_args).status();

        if web_ok && sec_ok {
            configured.push(svc.clone());
        }
    }
    Ok(configured)
}

/// Disables both system HTTP/HTTPS proxy and PAC across all active macOS network services.
pub fn disable_all_proxies() -> io::Result<Vec<String>> {
    let services = list_network_services()?;
    let mut disabled = Vec::new();
    for svc in &services {
        let a = Command::new("networksetup")
            .args(["-setwebproxystate", svc, "off"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let b = Command::new("networksetup")
            .args(["-setsecurewebproxystate", svc, "off"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let c = Command::new("networksetup")
            .args(["-setautoproxystate", svc, "off"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if a || b || c {
            disabled.push(svc.clone());
        }
    }
    Ok(disabled)
}

pub fn scutil_proxy_summary() -> String {
    Command::new("scutil")
        .arg("--proxy")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|e| format!("failed to run scutil: {e}"))
}

pub fn is_system_proxy_enabled(listen_addr: &str) -> bool {
    let port = listen_addr.rsplit_once(':').map(|(_, p)| p).unwrap_or("18080");
    let summary = scutil_proxy_summary();
    let http_on = summary.contains("HTTPEnable : 1") || summary.contains("HTTPSEnable : 1");
    let port_match = summary.contains(&format!("HTTPPort : {port}"))
        || summary.contains(&format!("HTTPSPort : {port}"));
    http_on && port_match
}

pub fn launch_agent_plist_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"))
}

pub fn log_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join("Library").join("Logs").join("swerve")
}

pub fn install_launch_agent(binary_path: &Path, config_path: &Path) -> io::Result<PathBuf> {
    let plist_path = launch_agent_plist_path();
    let logs = log_dir();
    fs::create_dir_all(&logs)?;
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let stdout_log = logs.join("swerve.log");
    let stderr_log = logs.join("swerve.err.log");

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>run</string>
        <string>--config</string>
        <string>{cfg}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardOutPath</key>
    <string>{out}</string>
    <key>StandardErrorPath</key>
    <string>{err}</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        bin = binary_path.display(),
        cfg = config_path.display(),
        out = stdout_log.display(),
        err = stderr_log.display(),
    );

    fs::write(&plist_path, plist)?;
    Ok(plist_path)
}

fn gui_domain() -> String {
    let uid = unsafe { libc::getuid() };
    format!("gui/{uid}")
}

pub fn launchctl_start(plist_path: &Path) -> io::Result<()> {
    let domain = gui_domain();
    let _ = Command::new("launchctl")
        .args(["bootout", &domain, &plist_path.to_string_lossy()])
        .output();

    let out = Command::new("launchctl")
        .args(["bootstrap", &domain, &plist_path.to_string_lossy()])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "launchctl bootstrap failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    Ok(())
}

pub fn launchctl_stop(plist_path: &Path) -> io::Result<()> {
    let domain = gui_domain();
    let _ = Command::new("launchctl")
        .args(["bootout", &domain, &plist_path.to_string_lossy()])
        .output()?;
    Ok(())
}

/// Sends SIGHUP to the running LaunchAgent so it hot-reloads `config.toml` without dropping connections.
pub fn signal_reload() -> bool {
    let domain_service = format!("{}/{}", gui_domain(), LAUNCHD_LABEL);
    Command::new("launchctl")
        .args(["kill", "HUP", &domain_service])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn is_agent_loaded() -> Option<u32> {
    let domain_service = format!("{}/{}", gui_domain(), LAUNCHD_LABEL);
    let out = Command::new("launchctl")
        .args(["print", &domain_service])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pid = ") {
            if let Ok(pid) = rest.trim().parse::<u32>() {
                return Some(pid);
            }
        }
    }
    Some(0)
}
