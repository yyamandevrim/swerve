mod config;
mod dns;
mod macos;
mod proxy;
mod tls;

use clap::{Parser, Subcommand, ValueEnum};
use config::{clean_domain, find_profile, BypassStrategy, Config, RoutingMode, BUILTIN_PROFILES};
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Parser)]
#[command(
    name = "swerve",
    version,
    about = "Fast, macOS-native DPI bypass proxy with zero-error auto-learn, persistent DoH, and live web UI"
)]
struct Cli {
    /// Custom path to config.toml (defaults to ~/.config/swerve/config.toml)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliStrategy {
    Combo,
    Chunk,
    TlsRecord,
    SniSplit,
    Skip,
}

impl From<CliStrategy> for BypassStrategy {
    fn from(s: CliStrategy) -> Self {
        match s {
            CliStrategy::Combo => BypassStrategy::Combo,
            CliStrategy::Chunk => BypassStrategy::Chunk,
            CliStrategy::TlsRecord => BypassStrategy::TlsRecord,
            CliStrategy::SniSplit => BypassStrategy::SniSplit,
            CliStrategy::Skip => BypassStrategy::Skip,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliMode {
    Smart,
    All,
    List,
}

impl From<CliMode> for RoutingMode {
    fn from(m: CliMode) -> Self {
        match m {
            CliMode::Smart => RoutingMode::Smart,
            CliMode::All => RoutingMode::All,
            CliMode::List => RoutingMode::List,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Run Swerve proxy & web UI in the foreground
    Run {
        #[arg(long)]
        listen: Option<String>,
        #[arg(long, value_enum)]
        mode: Option<CliMode>,
        #[arg(long, value_enum)]
        strategy: Option<CliStrategy>,
        #[arg(long)]
        chunk_size: Option<usize>,
        /// Temporarily configure macOS system proxy on startup and disable it on exit
        #[arg(long)]
        auto_proxy: bool,
        /// Log every proxied connection
        #[arg(short, long)]
        verbose: bool,
    },
    /// Install LaunchAgent, start Swerve at login, and enable macOS system proxy
    Install,
    /// Disable macOS system proxy, stop LaunchAgent, and remove the plist
    Uninstall,
    /// Start the LaunchAgent and enable macOS system proxy
    Start,
    /// Disable macOS system proxy and stop the LaunchAgent
    Stop,
    /// Restart the LaunchAgent
    Restart,
    /// Show daemon status, live metrics, and macOS proxy configuration
    Status,
    /// Open the Swerve live web dashboard in your default browser
    Ui,
    /// Switch routing mode (smart, all, list) and hot-reload daemon
    Mode {
        #[arg(value_enum)]
        mode: CliMode,
    },
    /// Manage built-in domain profiles (discord, roblox, pastebin, social, gaming, dev)
    Profiles {
        #[command(subcommand)]
        action: Option<ProfileAction>,
    },
    /// Manage custom bypass & exclude domains (hot-reloads running daemon via SIGHUP)
    Domains {
        #[command(subcommand)]
        action: DomainAction,
    },
    /// Test connectivity through Swerve (or benchmark all bypass strategies with --probe)
    Test {
        /// Benchmark all bypass strategies (combo, tls-record, chunk, sni-split)
        #[arg(long)]
        probe: bool,
        /// Optional custom host(s) to test (e.g. --url pastebin.com)
        #[arg(long)]
        url: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    List,
    Enable { id: String },
    Disable { id: String },
}

#[derive(Subcommand)]
enum DomainAction {
    List,
    Add { domain: String },
    Remove { domain: String },
    Exclude { domain: String },
    Unexclude { domain: String },
}

#[tokio::main]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn real_main() -> io::Result<()> {
    let cli = Cli::parse();
    let cfg_path = cli.config.unwrap_or_else(config::default_config_path);

    match cli.command {
        Commands::Run {
            listen,
            mode,
            strategy,
            chunk_size,
            auto_proxy,
            verbose,
        } => {
            let mut cfg = Config::load_or_create(&cfg_path)?;
            if let Some(l) = listen {
                cfg.listen_addr = l;
            }
            if let Some(m) = mode {
                cfg.mode = m.into();
            }
            if let Some(s) = strategy {
                cfg.strategy = s.into();
            }
            if let Some(c) = chunk_size {
                cfg.chunk_size = c;
            }
            proxy::run_server(cfg, cfg_path, auto_proxy, verbose).await
        }

        Commands::Install => {
            let cfg = Config::load_or_create(&cfg_path)?;
            let exe = std::env::current_exe()?.canonicalize()?;
            let plist = macos::install_launch_agent(&exe, &cfg_path)?;
            macos::launchctl_start(&plist)?;
            tokio::time::sleep(Duration::from_millis(400)).await;
            let svcs = macos::enable_system_proxy(&cfg.listen_addr)?;
            let bypass = macos::discover_bypass_domains();
            println!("Installed LaunchAgent: {}", plist.display());
            println!("Config:                {}", cfg_path.display());
            println!("Proxy:                 http://{}", cfg.listen_addr);
            println!("Web UI:                http://{}/ui", cfg.listen_addr);
            println!("Mode / Strategy:       {} / {} ({}B)", cfg.mode, cfg.strategy, cfg.chunk_size);
            println!("Enabled proxy on:      {}", svcs.join(", "));
            println!("Local/VPN bypass:      {}", bypass.join(", "));
            Ok(())
        }

        Commands::Uninstall => {
            let svcs = macos::disable_all_proxies().unwrap_or_default();
            let plist = macos::launch_agent_plist_path();
            let _ = macos::launchctl_stop(&plist);
            if plist.exists() {
                std::fs::remove_file(&plist)?;
            }
            println!("Disabled proxies on:   {}", svcs.join(", "));
            println!("Removed LaunchAgent:   {}", plist.display());
            Ok(())
        }

        Commands::Start => {
            let cfg = Config::load_or_create(&cfg_path)?;
            let plist = macos::launch_agent_plist_path();
            if !plist.exists() {
                let exe = std::env::current_exe()?.canonicalize()?;
                macos::install_launch_agent(&exe, &cfg_path)?;
            }
            macos::launchctl_start(&plist)?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            let svcs = macos::enable_system_proxy(&cfg.listen_addr)?;
            println!("Started Swerve (http://{})", cfg.listen_addr);
            println!("Web UI:                  http://{}/ui", cfg.listen_addr);
            println!("Enabled system proxy on: {}", svcs.join(", "));
            Ok(())
        }

        Commands::Stop => {
            let svcs = macos::disable_all_proxies().unwrap_or_default();
            let plist = macos::launch_agent_plist_path();
            let _ = macos::launchctl_stop(&plist);
            println!("Stopped Swerve and disabled proxies on: {}", svcs.join(", "));
            Ok(())
        }

        Commands::Restart => {
            let cfg = Config::load_or_create(&cfg_path)?;
            let plist = macos::launch_agent_plist_path();
            let exe = std::env::current_exe()?.canonicalize()?;
            macos::install_launch_agent(&exe, &cfg_path)?;
            macos::launchctl_start(&plist)?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            let svcs = macos::enable_system_proxy(&cfg.listen_addr)?;
            println!("Restarted Swerve (http://{}/ui)", cfg.listen_addr);
            println!("Enabled system proxy on: {}", svcs.join(", "));
            Ok(())
        }

        Commands::Status => {
            let cfg = Config::load_or_create(&cfg_path)?;
            println!("=== LaunchAgent ===");
            match macos::is_agent_loaded() {
                Some(pid) if pid > 0 => println!("dev.swerve.agent: running (PID {pid})"),
                Some(_) => println!("dev.swerve.agent: loaded (not running)"),
                None => println!("dev.swerve.agent: not loaded"),
            }
            println!("Config: {}", cfg_path.display());
            println!("Web UI: http://{}/ui", cfg.listen_addr);

            println!("\n=== Live Metrics (http://{}/status) ===", cfg.listen_addr);
            match http_get_local(&cfg.listen_addr, "/status").await {
                Ok(body) => println!("{body}"),
                Err(e) => println!("unreachable ({e})"),
            }

            println!("\n=== macOS System Proxy (scutil --proxy) ===");
            print!("{}", macos::scutil_proxy_summary());
            Ok(())
        }

        Commands::Ui => {
            let cfg = Config::load_or_create(&cfg_path)?;
            let url = format!("http://{}/ui", cfg.listen_addr);
            println!("Opening {url}");
            Command::new("open").arg(&url).status()?;
            Ok(())
        }

        Commands::Mode { mode } => {
            let mut cfg = Config::load_or_create(&cfg_path)?;
            cfg.mode = mode.into();
            cfg.save(&cfg_path)?;
            let reloaded = macos::signal_reload();
            println!(
                "Routing mode set to '{}' (hot-reload: {})",
                cfg.mode,
                if reloaded { "ok" } else { "daemon not running" }
            );
            Ok(())
        }

        Commands::Profiles { action } => {
            let mut cfg = Config::load_or_create(&cfg_path)?;
            match action.unwrap_or(ProfileAction::List) {
                ProfileAction::List => {
                    for p in BUILTIN_PROFILES {
                        let on = cfg.profiles.iter().any(|x| x.eq_ignore_ascii_case(p.id));
                        println!(
                            "  [{:3}] {:<10} ({:>2} domains) — {}",
                            if on { "ON" } else { "OFF" },
                            p.id,
                            p.domains.len(),
                            p.description
                        );
                    }
                }
                ProfileAction::Enable { id } => {
                    let Some(p) = find_profile(&id) else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("unknown profile '{id}' (run `swerve profiles list`)"),
                        ));
                    };
                    if !cfg.profiles.iter().any(|x| x.eq_ignore_ascii_case(p.id)) {
                        cfg.profiles.push(p.id.to_string());
                        cfg.save(&cfg_path)?;
                    }
                    let reloaded = macos::signal_reload();
                    println!(
                        "Enabled profile '{}' (hot-reload: {})",
                        p.id,
                        if reloaded { "ok" } else { "daemon not running" }
                    );
                }
                ProfileAction::Disable { id } => {
                    cfg.profiles.retain(|x| !x.eq_ignore_ascii_case(&id));
                    cfg.save(&cfg_path)?;
                    let reloaded = macos::signal_reload();
                    println!(
                        "Disabled profile '{}' (hot-reload: {})",
                        id,
                        if reloaded { "ok" } else { "daemon not running" }
                    );
                }
            }
            Ok(())
        }

        Commands::Domains { action } => {
            let mut cfg = Config::load_or_create(&cfg_path)?;
            match action {
                DomainAction::List => {
                    println!("Enabled profiles: {}", cfg.profiles.join(", "));
                    println!("Custom bypass ({}):", cfg.domains.len());
                    for d in &cfg.domains {
                        println!("  + {d}");
                    }
                    println!("Excluded ({}):", cfg.exclude_domains.len());
                    for d in &cfg.exclude_domains {
                        println!("  - {d}");
                    }
                }
                DomainAction::Add { domain } => {
                    let clean = clean_domain(&domain);
                    cfg.exclude_domains.retain(|d| !d.eq_ignore_ascii_case(&clean));
                    if !cfg.domains.iter().any(|d| d.eq_ignore_ascii_case(&clean)) {
                        cfg.domains.push(clean.clone());
                        cfg.save(&cfg_path)?;
                    }
                    let reloaded = macos::signal_reload();
                    println!(
                        "Added {clean} (hot-reload: {})",
                        if reloaded { "ok" } else { "daemon not running" }
                    );
                }
                DomainAction::Remove { domain } => {
                    let clean = clean_domain(&domain);
                    cfg.domains.retain(|d| !d.eq_ignore_ascii_case(&clean));
                    cfg.save(&cfg_path)?;
                    let reloaded = macos::signal_reload();
                    println!(
                        "Removed {clean} (hot-reload: {})",
                        if reloaded { "ok" } else { "daemon not running" }
                    );
                }
                DomainAction::Exclude { domain } => {
                    let clean = clean_domain(&domain);
                    cfg.domains.retain(|d| !d.eq_ignore_ascii_case(&clean));
                    if !cfg.exclude_domains.iter().any(|d| d.eq_ignore_ascii_case(&clean)) {
                        cfg.exclude_domains.push(clean.clone());
                        cfg.save(&cfg_path)?;
                    }
                    let reloaded = macos::signal_reload();
                    println!(
                        "Excluded {clean} (hot-reload: {})",
                        if reloaded { "ok" } else { "daemon not running" }
                    );
                }
                DomainAction::Unexclude { domain } => {
                    let clean = clean_domain(&domain);
                    cfg.exclude_domains.retain(|d| !d.eq_ignore_ascii_case(&clean));
                    cfg.save(&cfg_path)?;
                    let reloaded = macos::signal_reload();
                    println!(
                        "Unexcluded {clean} (hot-reload: {})",
                        if reloaded { "ok" } else { "daemon not running" }
                    );
                }
            }
            Ok(())
        }

        Commands::Test { probe, url } => {
            let cfg = Config::load_or_create(&cfg_path)?;
            if probe {
                probe_strategies(&cfg).await?;
                return Ok(());
            }

            let targets: Vec<String> = if url.is_empty() {
                vec![
                    "https://discord.com".into(),
                    "https://gateway.discord.gg".into(),
                    "https://cdn.discordapp.com".into(),
                    "https://pastebin.com".into(),
                    "https://roblox.com".into(),
                    "https://example.com".into(),
                ]
            } else {
                url.into_iter()
                    .map(|u| {
                        if u.starts_with("http://") || u.starts_with("https://") {
                            u
                        } else {
                            format!("https://{u}")
                        }
                    })
                    .collect()
            };

            println!("=== Direct proxy test (http://{}) ===", cfg.listen_addr);
            for target in &targets {
                let t0 = Instant::now();
                let out = Command::new("curl")
                    .args([
                        "-s",
                        "-o",
                        "/dev/null",
                        "-w",
                        "HTTP %{http_code} (exit:%{exitcode})",
                        "-m",
                        "6",
                        "-x",
                        &format!("http://{}", cfg.listen_addr),
                        target,
                    ])
                    .output()?;
                let status = String::from_utf8_lossy(&out.stdout);
                println!(
                    "  {target:<30} -> {status} ({:.0}ms)",
                    t0.elapsed().as_secs_f64() * 1000.0
                );
            }

            println!("\n=== macOS native URLSession test (no proxy flag) ===");
            let swift_code = r#"
import Foundation
let sem = DispatchSemaphore(value: 0)
for urlStr in ["https://discord.com", "https://gateway.discord.gg", "https://pastebin.com", "https://example.com"] {
    let url = URL(string: urlStr)!
    var req = URLRequest(url: url)
    req.timeoutInterval = 8
    URLSession.shared.dataTask(with: req) { _, resp, err in
        if let http = resp as? HTTPURLResponse {
            print("  \(urlStr) -> HTTP \(http.statusCode)")
        } else {
            print("  \(urlStr) -> ERR \(err?.localizedDescription ?? "unknown")")
        }
        sem.signal()
    }.resume()
    sem.wait()
}
"#;
            let out = Command::new("swift").args(["-e", swift_code]).output()?;
            print!("{}", String::from_utf8_lossy(&out.stdout));
            Ok(())
        }
    }
}

async fn http_get_local(addr: &str, path: &str) -> io::Result<String> {
    let mut stream = TcpStream::connect(addr).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    if let Some((_, body)) = text.split_once("\r\n\r\n") {
        Ok(body.to_string())
    } else {
        Ok(text.to_string())
    }
}

async fn probe_strategies(base_cfg: &Config) -> io::Result<()> {
    let strategies = [
        ("combo (tls-record + chunk=2)", BypassStrategy::Combo, 2),
        ("tls-record (SNI record split)", BypassStrategy::TlsRecord, 2),
        ("chunk=2", BypassStrategy::Chunk, 2),
        ("chunk=1", BypassStrategy::Chunk, 1),
        ("sni-split (TCP segment split)", BypassStrategy::SniSplit, 2),
    ];

    println!("Probing strategies against https://discord.com & https://gateway.discord.gg...");
    for (idx, (label, strat, chunk)) in strategies.iter().enumerate() {
        let port = 18190 + idx as u16;
        let addr = format!("127.0.0.1:{port}");
        let mut cfg = base_cfg.clone();
        cfg.listen_addr = addr.clone();
        cfg.mode = RoutingMode::All;
        cfg.strategy = *strat;
        cfg.chunk_size = *chunk;

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        let state = std::sync::Arc::new(proxy::ServerState {
            config: tokio::sync::RwLock::new(cfg),
            config_path: config::default_config_path(),
            resolver: dns::Resolver::new(),
            stats: proxy::Stats::new(),
        });

        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let st = std::sync::Arc::clone(&state);
                        tokio::spawn(async move {
                            let _ = proxy::handle_probe_connection(stream, st).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let t0 = Instant::now();
        let out1 = Command::new("curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-m",
                "5",
                "-x",
                &format!("http://{addr}"),
                "https://discord.com",
            ])
            .output()?;
        let code1 = String::from_utf8_lossy(&out1.stdout).to_string();
        let out2 = Command::new("curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-m",
                "5",
                "-x",
                &format!("http://{addr}"),
                "https://gateway.discord.gg",
            ])
            .output()?;
        let code2 = String::from_utf8_lossy(&out2.stdout).to_string();
        let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
        let ok = code1 == "200" && code2 == "404";
        println!(
            "  {:<32} -> discord.com={code1:<3} gateway={code2:<3} ({elapsed:.0}ms) {}",
            label,
            if ok { "OK" } else { "BLOCKED" }
        );
        task.abort();
    }
    Ok(())
}
