use clap::Parser;
use eyre::{Context, Result};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, instrument, warn};

// Constants
const SOURCE_DNS: &str = "httpdns.ctdns.cn";
const TARGET_DOMAIN: &str = "tlu.dl.delivery.mp.microsoft.com";

#[cfg(windows)]
const NEWLINE: &str = "\r\n";
#[cfg(not(windows))]
const NEWLINE: &str = "\n";

/// Updates the system hosts file with a specific DNS resolution.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run without modifying the file
    #[arg(long)]
    dry_run: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Custom input hosts file location (default: system hosts file)
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Custom output hosts file location (default: overwrites input file)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize Error Handling and Argument Parsing
    color_eyre::install().ok();
    let args = Args::parse();

    // 2. Initialize Logging
    let log_level = if args.debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(args.debug)
        .without_time()
        .init();

    if args.dry_run {
        warn!("DRY RUN MODE: No files will be modified.");
    }

    // 3. Resolve IP
    info!("Resolving IP for: {} ...", SOURCE_DNS);
    let ips = resolve_ip(SOURCE_DNS).await.wrap_err("Failed to resolve DNS")?;

    debug!("Resolved IP list: {:?}", ips);

    // 4. Select IPv4
    let target_ip = ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| ips.first())
        .ok_or_else(|| eyre::eyre!("No IP address found for {}", SOURCE_DNS))?;

    info!("Selected IP: {}", target_ip);

    // 5. Determine Paths
    let system_hosts_path = get_hosts_file_path();
    
    // Logic: Use arg -> fallback to system path
    let input_path = args.input.as_deref().unwrap_or(&system_hosts_path);
    
    // Logic: Use arg -> fallback to input path (overwrite)
    let output_path = args.output.as_deref().unwrap_or(input_path);

    debug!("Input path: {:?}", input_path);
    debug!("Output path: {:?}", output_path);

    // 6. Update File
    match update_hosts_file(input_path, output_path, TARGET_DOMAIN, *target_ip, args.dry_run).await {
        Ok(_) => {
            if args.dry_run {
                info!("Simulation completed successfully.");
            } else {
                info!("Hosts file updated successfully.");
            }
        }
        Err(e) => {
            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                    error!("Permission Denied!");
                    if cfg!(windows) {
                        warn!("Please run the terminal as Administrator.");
                    } else {
                        warn!("Please run using sudo.");
                    }
                }
            }
            return Err(e).wrap_err("Failed to update hosts file");
        }
    }

    Ok(())
}

#[instrument]
async fn resolve_ip(hostname: &str) -> std::io::Result<Vec<IpAddr>> {
    let addrs = tokio::net::lookup_host((hostname, 0)).await?;
    Ok(addrs.map(|socket_addr| socket_addr.ip()).collect())
}

fn get_hosts_file_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

async fn update_hosts_file(
    input_path: &Path,
    output_path: &Path,
    domain: &str,
    ip: IpAddr,
    dry_run: bool,
) -> Result<()> {
    // Read existing content
    info!("Reading from {:?}", input_path);
    let content = tokio::fs::read_to_string(input_path)
        .await
        .wrap_err_with(|| format!("Could not read file at {:?}", input_path))?;

    // Pre-allocate String buffer
    let mut new_content = String::with_capacity(content.len() + 64);
    let mut found_old = false;

    // Process line by line
    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            new_content.push_str(line);
            new_content.push_str(NEWLINE);
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let is_target_record = parts.len() > 1 && parts[1..].contains(&domain);

        if is_target_record {
            found_old = true;
            debug!("Removing old record: {}", line);
            continue;
        }

        new_content.push_str(line);
        new_content.push_str(NEWLINE);
    }

    if !found_old {
        debug!("No existing record found for {}", domain);
    }

    // Prepare new record
    let new_record = format!("{} {}", ip, domain);
    info!("Adding new record: {}", new_record);

    new_content.push_str(&new_record);
    new_content.push_str(NEWLINE);

    if dry_run {
        warn!("Dry run enabled. Skipping write operation to {:?}", output_path);
        return Ok(());
    }

    debug!("Writing {} bytes to {:?}", new_content.len(), output_path);
    tokio::fs::write(output_path, new_content)
        .await
        .wrap_err_with(|| format!("Failed to write to {:?}", output_path))?;

    Ok(())
}
