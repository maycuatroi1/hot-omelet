use clap::Parser;
use ipnet::Ipv4Net;
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};

#[derive(Parser)]
#[command(name = "ping-sweep", about = "High-performance network host discovery")]
struct Args {
    /// Target network in CIDR notation (e.g. 10.30.148.0/22), single IP, or "auto"
    #[arg(default_value = "auto")]
    network: String,

    /// Maximum concurrent host probes
    #[arg(short = 'c', long, default_value = "512")]
    concurrency: usize,

    /// Timeout per port probe in milliseconds
    #[arg(short = 't', long, default_value = "500")]
    timeout_ms: u64,

    /// TCP ports to probe (comma-separated). First hit = alive, rest in parallel.
    #[arg(short = 'p', long, default_value = "80,443,22,445,8080,3389,21,23,53,8443,554,3306,5432,6379,9100")]
    ports: String,

    /// Output format: text, json, csv
    #[arg(short = 'o', long, default_value = "text")]
    output: String,

    /// Only show alive hosts (one IP per line, no decoration)
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Use system ping (ICMP) instead of TCP connect
    #[arg(long)]
    icmp: bool,

    /// Scan common private ranges reachable from this host (10.x, 172.16-31, 192.168)
    #[arg(long)]
    wide: bool,
}

#[derive(Serialize, Clone, Debug)]
struct HostResult {
    ip: String,
    alive: bool,
    rtt_ms: f64,
    method: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    open_ports: Vec<u16>,
}

/// Try TCP connect to a single port. Returns Some(rtt_ms) if alive (connect or refused).
fn try_port(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<f64> {
    let addr = SocketAddr::from((ip, port));
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Some(start.elapsed().as_secs_f64() * 1000.0),
        Err(e) => {
            if e.to_string().contains("refused") {
                Some(start.elapsed().as_secs_f64() * 1000.0)
            } else {
                None
            }
        }
    }
}

/// Probe host with early-exit: try first 3 common ports quickly, if any responds we know it's alive.
/// Then scan remaining ports in parallel threads for port discovery.
async fn tcp_probe(ip: Ipv4Addr, ports: Vec<u16>, timeout_ms: u64) -> (bool, f64, Vec<u16>) {
    let result = tokio::task::spawn_blocking(move || {
        let timeout = Duration::from_millis(timeout_ms);
        let mut open = Vec::new();
        let mut best_rtt = f64::MAX;

        // Phase 1: Quick check first 3 ports with short timeout for early exit
        let quick_timeout = Duration::from_millis(timeout_ms.min(300));
        let quick_ports = &ports[..ports.len().min(3)];

        for &port in quick_ports {
            if let Some(rtt) = try_port(ip, port, quick_timeout) {
                if rtt < best_rtt {
                    best_rtt = rtt;
                }
                open.push(port);
            }
        }

        // Phase 2: If alive from quick check, scan remaining ports in parallel threads
        // If not alive yet, try remaining ports with full timeout
        let remaining: Vec<u16> = if !open.is_empty() {
            ports[quick_ports.len()..].to_vec()
        } else {
            // Try remaining with full timeout
            for &port in &ports[quick_ports.len()..] {
                if let Some(rtt) = try_port(ip, port, timeout) {
                    if rtt < best_rtt {
                        best_rtt = rtt;
                    }
                    open.push(port);
                    // Found alive! Collect rest in parallel
                    break;
                }
            }
            if open.is_empty() {
                return (false, 0.0, vec![]);
            }
            // Get ports we haven't tried yet
            let tried = quick_ports.len() + ports[quick_ports.len()..].iter()
                .position(|p| open.contains(p))
                .map(|i| i + 1)
                .unwrap_or(ports.len() - quick_ports.len());
            ports[tried + quick_ports.len()..].to_vec()
        };

        // Scan remaining ports using thread pool for speed
        if !remaining.is_empty() {
            let handles: Vec<_> = remaining
                .into_iter()
                .map(|port| {
                    let timeout = timeout;
                    std::thread::spawn(move || {
                        let addr = SocketAddr::from((ip, port));
                        match TcpStream::connect_timeout(&addr, timeout) {
                            Ok(_) => Some(port),
                            _ => None,
                        }
                    })
                })
                .collect();

            for h in handles {
                if let Ok(Some(port)) = h.join() {
                    open.push(port);
                }
            }
        }

        open.sort();
        let alive = best_rtt < f64::MAX;
        if !alive {
            best_rtt = 0.0;
        }
        (alive, best_rtt, open)
    })
    .await;

    result.unwrap_or((false, 0.0, vec![]))
}

/// Probe using system ping command.
async fn icmp_probe(ip: Ipv4Addr, timeout_ms: u64) -> (bool, f64) {
    let result = tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let output = Command::new("ping")
            .args([
                "-c", "1",
                "-W", &format!("{}", timeout_ms),
                &ip.to_string(),
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                (true, rtt)
            }
            _ => (false, 0.0),
        }
    })
    .await;

    result.unwrap_or((false, 0.0))
}

/// Auto-detect local network interfaces and their subnets.
/// If `wide` is true, also scan adjacent /24 subnets and common gateway ranges.
fn detect_networks(wide: bool) -> Vec<Ipv4Net> {
    let mut nets = Vec::new();

    // Parse ifconfig output to find interfaces with IP addresses
    if let Ok(output) = Command::new("ifconfig").output() {
        let text = String::from_utf8_lossy(&output.stdout);
        let mut current_ip: Option<Ipv4Addr> = None;
        let mut current_mask: Option<Ipv4Addr> = None;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") && !trimmed.contains("127.0.0.1") {
                // Parse: inet 10.22.64.68 netmask 0xffffff00 broadcast ...
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if let Some(pos) = parts.iter().position(|&s| s == "inet") {
                    if let Some(ip_str) = parts.get(pos + 1) {
                        current_ip = ip_str.parse().ok();
                    }
                }
                if let Some(pos) = parts.iter().position(|&s| s == "netmask") {
                    if let Some(mask_str) = parts.get(pos + 1) {
                        // Handle hex mask (0xffffff00) or dotted (255.255.255.0)
                        current_mask = if mask_str.starts_with("0x") {
                            u32::from_str_radix(&mask_str[2..], 16)
                                .ok()
                                .map(|m| Ipv4Addr::from(m))
                        } else {
                            mask_str.parse().ok()
                        };
                    }
                }

                if let (Some(ip), Some(mask)) = (current_ip, current_mask) {
                    // Calculate prefix length from mask
                    let mask_bits = u32::from(mask);
                    let prefix = mask_bits.count_ones() as u8;
                    if let Ok(net) = Ipv4Net::new(ip, prefix) {
                        let net = net.trunc(); // Normalize to network address
                        if !nets.contains(&net) {
                            nets.push(net);
                        }
                    }
                    current_ip = None;
                    current_mask = None;
                }
            }
        }
    }

    if wide {
        // Also check routing table for additional networks
        if let Ok(output) = Command::new("netstat").args(["-rn"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Look for routes like 10.30.148/22
                if parts.len() >= 2 {
                    if let Ok(net) = parts[0].parse::<Ipv4Net>() {
                        let net = net.trunc();
                        if net.prefix_len() >= 16 && !net.addr().is_loopback() && !nets.contains(&net) {
                            nets.push(net);
                        }
                    }
                }
            }
        }
    }

    if nets.is_empty() {
        eprintln!("Could not detect any network interfaces. Specify a network manually.");
        std::process::exit(1);
    }

    nets
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let ports: Vec<u16> = args
        .ports
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    // Resolve networks to scan
    let networks: Vec<Ipv4Net> = if args.network == "auto" || args.wide {
        detect_networks(args.wide)
    } else {
        vec![args.network.parse().unwrap_or_else(|_| {
            if let Ok(ip) = args.network.parse::<Ipv4Addr>() {
                Ipv4Net::new(ip, 32).unwrap()
            } else {
                eprintln!("Invalid network: {}", args.network);
                std::process::exit(1);
            }
        })]
    };

    let mut hosts: Vec<Ipv4Addr> = Vec::new();
    for net in &networks {
        hosts.extend(net.hosts());
    }
    // Dedup (in case of overlapping ranges)
    hosts.sort();
    hosts.dedup();
    let total = hosts.len();

    if total == 0 {
        eprintln!("No hosts found in specified networks");
        std::process::exit(1);
    }

    let method = if args.icmp { "icmp" } else { "tcp" };
    let net_str = networks.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");

    if !args.quiet && args.output == "text" {
        eprintln!(
            "Ping sweep: {} ({} hosts, concurrency={}, timeout={}ms, method={})",
            net_str, total, args.concurrency, args.timeout_ms, method
        );
    }

    let sem = Arc::new(Semaphore::new(args.concurrency));
    let results: Arc<Mutex<BTreeMap<Ipv4Addr, HostResult>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    let alive_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let start = Instant::now();
    let mut handles = Vec::with_capacity(total);

    for ip in hosts.iter().copied() {
        let sem = sem.clone();
        let results = results.clone();
        let alive_counter = alive_counter.clone();
        let timeout_ms = args.timeout_ms;
        let ports = ports.clone();
        let use_icmp = args.icmp;

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let (alive, rtt, open_ports, meth) = if use_icmp {
                let (alive, rtt) = icmp_probe(ip, timeout_ms).await;
                (alive, rtt, vec![], "icmp".to_string())
            } else {
                let (alive, rtt, open) = tcp_probe(ip, ports, timeout_ms).await;
                (alive, rtt, open, "tcp".to_string())
            };

            if alive {
                alive_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                results.lock().await.insert(
                    ip,
                    HostResult {
                        ip: ip.to_string(),
                        alive,
                        rtt_ms: rtt,
                        method: meth,
                        open_ports,
                    },
                );
            }
        });

        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }

    let elapsed = start.elapsed();
    let results = results.lock().await;
    let alive_count = results.len();

    match args.output.as_str() {
        "json" => {
            let alive: Vec<&HostResult> = results.values().collect();
            println!("{}", serde_json::to_string_pretty(&alive).unwrap());
        }
        "csv" => {
            println!("ip,rtt_ms,method,open_ports");
            for r in results.values() {
                let ports_str: Vec<String> = r.open_ports.iter().map(|p| p.to_string()).collect();
                println!("{},{:.2},{},{}", r.ip, r.rtt_ms, r.method, ports_str.join(";"));
            }
        }
        _ => {
            for r in results.values() {
                if args.quiet {
                    println!("{}", r.ip);
                } else {
                    let ports_str = if r.open_ports.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " ports=[{}]",
                            r.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
                        )
                    };
                    println!(
                        "\x1b[32m  ALIVE\x1b[0m  {:<18} {:>7.2}ms  ({}){}",
                        r.ip, r.rtt_ms, r.method, ports_str
                    );
                }
            }
            if !args.quiet {
                eprintln!(
                    "\n{}/{} hosts alive in {:.2}s ({:.0} hosts/sec)",
                    alive_count, total, elapsed.as_secs_f64(), total as f64 / elapsed.as_secs_f64()
                );
            }
        }
    }
}
