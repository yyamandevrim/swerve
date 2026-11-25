use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:18080";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingMode {
    /// Bypass enabled profiles + custom domains, and transparently auto-learn any site hit by DPI reset.
    Smart,
    /// Apply DPI bypass to all HTTPS traffic (except `exclude_domains`).
    All,
    /// Strict allowlist: only bypass enabled profiles + custom domains (no auto-learn).
    List,
}

impl std::fmt::Display for RoutingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Smart => write!(f, "smart"),
            Self::All => write!(f, "all"),
            Self::List => write!(f, "list"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BypassStrategy {
    /// Combine TLS record fragmentation across the SNI with small TCP_NODELAY chunking.
    Combo,
    /// Split TLS ClientHello into small TCP writes (`chunk_size` bytes) with TCP_NODELAY.
    Chunk,
    /// Split TLS ClientHello across two valid TLS handshake records right inside the SNI.
    TlsRecord,
    /// Split TLS ClientHello into two TCP segments right in the middle of the SNI hostname.
    SniSplit,
    /// Pass TLS traffic through unmodified.
    Skip,
}

impl std::fmt::Display for BypassStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Combo => write!(f, "combo"),
            Self::Chunk => write!(f, "chunk"),
            Self::TlsRecord => write!(f, "tls-record"),
            Self::SniSplit => write!(f, "sni-split"),
            Self::Skip => write!(f, "skip"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltinProfileInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub domains: &'static [&'static str],
}

pub const BUILTIN_PROFILES: &[BuiltinProfileInfo] = &[
    BuiltinProfileInfo {
        id: "discord",
        label: "Discord",
        description: "Discord app, updates, CDN, media & voice signaling",
        domains: &[
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
            "discord.media",
            "discord.co",
            "discordstatus.com",
            "dis.gd",
            "discord.new",
            "discord.gift",
            "discord.gifts",
            "discord.design",
            "discord.dev",
            "discord.store",
            "discord.tools",
            "discord.app",
            "discordcdn.com",
            "discord-attachments-uploads-prd.storage.googleapis.com",
        ],
    },
    BuiltinProfileInfo {
        id: "roblox",
        label: "Roblox",
        description: "Roblox web, client, CDN & assets",
        domains: &[
            "roblox.com",
            "rbxcdn.com",
            "robloxlabs.com",
            "rbx.com",
        ],
    },
    BuiltinProfileInfo {
        id: "pastebin",
        label: "Pastebin & Docs",
        description: "Pastebin, ImgBB, Imgur & commonly filtered paste/image hosts",
        domains: &[
            "pastebin.com",
            "imgur.com",
            "i.imgur.com",
            "wattpad.com",
        ],
    },
    BuiltinProfileInfo {
        id: "social",
        label: "Social & Chat",
        description: "Instagram, X/Twitter, Telegram web & Reddit",
        domains: &[
            "instagram.com",
            "cdninstagram.com",
            "x.com",
            "twitter.com",
            "twimg.com",
            "t.me",
            "telegram.org",
            "reddit.com",
            "redd.it",
            "redditmedia.com",
        ],
    },
    BuiltinProfileInfo {
        id: "gaming",
        label: "Gaming & Voice",
        description: "Twitch, Steam community, Kick & Riot",
        domains: &[
            "twitch.tv",
            "ttvnw.net",
            "kick.com",
            "steamcommunity.com",
        ],
    },
    BuiltinProfileInfo {
        id: "dev",
        label: "Dev & Knowledge",
        description: "Wikipedia, Archive.org, Medium & SoundCloud",
        domains: &[
            "wikipedia.org",
            "wikimedia.org",
            "archive.org",
            "web.archive.org",
            "medium.com",
            "soundcloud.com",
        ],
    },
];

pub fn find_profile(id: &str) -> Option<&'static BuiltinProfileInfo> {
    BUILTIN_PROFILES
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(id))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Local bind address for the proxy, web UI (`/ui`), APIs, and `/proxy.pac`.
    pub listen_addr: String,
    /// General routing mode: `smart` (profiles + domains + auto-learn), `all`, or `list`.
    pub mode: RoutingMode,
    /// Automatically detect DPI resets on direct connections and transparently retry with bypass.
    pub auto_learn: bool,
    /// Bypass strategy for matched connections.
    pub strategy: BypassStrategy,
    /// Chunk size in bytes for `chunk` and `combo` strategies (1..=64).
    pub chunk_size: usize,
    /// Optional delay in microseconds between TCP chunks (0 = rely on TCP_NODELAY).
    pub chunk_delay_us: u64,
    /// Number of low-TTL fake ClientHello packets to send before the real one (0 = disabled).
    pub fake_count: u8,
    /// IP TTL used for fake ClientHello packets (e.g. 4..=10 so packets drop after the ISP DPI box).
    pub fake_ttl: u8,
    /// Use DNS-over-HTTPS for bypassed domains to defeat DNS poisoning.
    pub doh_for_matched: bool,
    /// Primary and fallback DoH server IPs (connected directly by IP to avoid DNS hijacking).
    pub doh_servers: Vec<String>,
    /// Connection timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Enabled built-in domain profile IDs.
    pub profiles: Vec<String>,
    /// User-added custom domains to bypass (exact match + all subdomains).
    pub domains: Vec<String>,
    /// Domains that must always go direct and never be bypassed or auto-learned.
    pub exclude_domains: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
            mode: RoutingMode::Smart,
            auto_learn: true,
            strategy: BypassStrategy::Combo,
            chunk_size: 2,
            chunk_delay_us: 0,
            fake_count: 0,
            fake_ttl: 6,
            doh_for_matched: true,
            doh_servers: vec![
                "1.1.1.1".to_string(),
                "1.0.0.1".to_string(),
                "8.8.8.8".to_string(),
            ],
            connect_timeout_ms: 8000,
            profiles: vec!["discord".to_string()],
            domains: Vec::new(),
            exclude_domains: vec![
                "apple.com".to_string(),
                "icloud.com".to_string(),
                "mzstatic.com".to_string(),
                "tailscale.com".to_string(),
                "ts.net".to_string(),
            ],
        }
    }
}

pub fn default_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config").join("swerve").join("config.toml")
}

pub fn clean_domain(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("*.")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub fn domain_matches_rule(host: &str, rule: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let d = rule
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if d.is_empty() {
        return false;
    }
    h == d || (h.len() > d.len() && h.ends_with(&d) && h.as_bytes()[h.len() - d.len() - 1] == b'.')
}

/// Extracts a reasonable registrable base domain for auto-learning (e.g. `cdn.foo.com` -> `foo.com`).
pub fn base_domain_for_learn(host: &str) -> String {
    let h = clean_domain(host);
    if h.parse::<std::net::IpAddr>().is_ok() {
        return h;
    }
    let parts: Vec<&str> = h.split('.').filter(|s| !s.is_empty()).collect();
    if parts.len() <= 2 {
        return h;
    }
    // Preserve common 2-level public suffixes like .co.uk, .com.tr, .org.tr
    let last2 = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    let multi_tld = matches!(
        last2.as_str(),
        "com.tr" | "org.tr" | "net.tr" | "gov.tr" | "edu.tr" | "co.uk" | "org.uk" | "com.au" | "co.jp" | "com.br"
    );
    if multi_tld && parts.len() >= 3 {
        format!("{}.{}.{}", parts[parts.len() - 3], parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        last2
    }
}

impl Config {
    pub fn load(path: &Path) -> io::Result<Self> {
        let raw = fs::read_to_string(path)?;
        toml::from_str(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let cfg = Self::default();
            cfg.save(path)?;
            Ok(cfg)
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let body = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let header = "# Swerve configuration (SIGHUP hot-reloads changes)\n\n";
        fs::write(path, format!("{header}{body}"))
    }

    pub fn is_excluded(&self, host: &str) -> bool {
        self.exclude_domains
            .iter()
            .any(|rule| domain_matches_rule(host, rule))
    }

    /// Returns all active configured bypass domains (enabled profiles + custom domains).
    pub fn effective_domains(&self) -> Vec<String> {
        let mut out = Vec::new();
        for pid in &self.profiles {
            if let Some(prof) = find_profile(pid) {
                for d in prof.domains {
                    let s = (*d).to_string();
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
        }
        for d in &self.domains {
            let clean = clean_domain(d);
            if !clean.is_empty() && !out.contains(&clean) {
                out.push(clean);
            }
        }
        out
    }

    /// Returns true if `host` explicitly matches enabled profiles or custom domains.
    pub fn matches_configured_domain(&self, host: &str) -> bool {
        if self.is_excluded(host) {
            return false;
        }
        for pid in &self.profiles {
            if let Some(prof) = find_profile(pid) {
                if prof.domains.iter().any(|d| domain_matches_rule(host, d)) {
                    return true;
                }
            }
        }
        self.domains.iter().any(|d| domain_matches_rule(host, d))
    }

    /// Dynamically generates a PAC script for environments that prefer PAC over system proxy.
    pub fn generate_pac(&self) -> String {
        if self.mode == RoutingMode::All {
            return format!(
                "function FindProxyForURL(url, host) {{\n  if (isPlainHostName(host) || shExpMatch(host, \"*.local\") || shExpMatch(host, \"*.ts.net\")) return \"DIRECT\";\n  return \"PROXY {}; DIRECT\";\n}}\n",
                self.listen_addr
            );
        }

        let domains_js: Vec<String> = self
            .effective_domains()
            .into_iter()
            .map(|d| format!("    {d:?}"))
            .collect();

        format!(
            "function FindProxyForURL(url, host) {{\n  var h = host.toLowerCase();\n  var domains = [\n{}\n  ];\n  for (var i = 0; i < domains.length; i++) {{\n    var d = domains[i];\n    if (h === d || dnsDomainIs(h, \".\" + d)) {{\n      return \"PROXY {}; DIRECT\";\n    }}\n  }}\n  return \"DIRECT\";\n}}\n",
            domains_js.join(",\n"),
            self.listen_addr
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_exclude_matching() {
        let mut cfg = Config::default();
        assert!(cfg.matches_configured_domain("discord.com"));
        assert!(cfg.matches_configured_domain("gateway.discord.gg"));
        assert!(!cfg.matches_configured_domain("roblox.com"));
        assert!(!cfg.matches_configured_domain("icloud.com"));

        cfg.profiles.push("roblox".to_string());
        assert!(cfg.matches_configured_domain("www.roblox.com"));

        cfg.exclude_domains.push("discord.com".to_string());
        assert!(!cfg.matches_configured_domain("discord.com"));
    }

    #[test]
    fn base_domain_extraction() {
        assert_eq!(base_domain_for_learn("cdn.discord.com"), "discord.com");
        assert_eq!(base_domain_for_learn("foo.bar.com.tr"), "bar.com.tr");
        assert_eq!(base_domain_for_learn("example.org"), "example.org");
    }
}
