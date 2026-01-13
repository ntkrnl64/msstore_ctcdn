use clap::Parser;
use eyre::{Context, Result};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, instrument};

#[cfg(target_os = "windows")]
use native_windows_derive::NwgUi;
#[cfg(target_os = "windows")]
use native_windows_gui as nwg;
#[cfg(target_os = "windows")]
use native_windows_gui::NativeUi;

const SOURCE_DNS: &str = "httpdns.ctdns.cn";
const TARGET_DOMAIN: &str = "tlu.dl.delivery.mp.microsoft.com";

#[cfg(windows)]
const NEWLINE: &str = "\r\n";
#[cfg(not(windows))]
const NEWLINE: &str = "\n";

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run without modifying the file
    #[arg(long)]
    dry_run: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Custom input hosts file location
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Custom output hosts file location
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    color_eyre::install().ok();

    let args_raw: Vec<String> = std::env::args().collect();
    let has_args = args_raw.len() > 1;

    #[cfg(target_os = "windows")]
    let double_clicked = is_double_clicked();
    #[cfg(not(target_os = "windows"))]
    let double_clicked = false;

    if has_args || !double_clicked {
        run_cli_mode()
    } else {
        #[cfg(target_os = "windows")]
        {
            run_gui_mode()
        }
        #[cfg(not(target_os = "windows"))]
        {
            println!("GUI mode is only available on Windows.");
            run_cli_mode()
        }
    }
}

fn run_cli_mode() -> Result<()> {
    let args = Args::parse();

    // Init Logging
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

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(core_logic(args, None))
}

/// The core logic shared by both CLI and GUI
async fn core_logic(args: Args, gui_logger: Option<Arc<Mutex<String>>>) -> Result<()> {
    // Helper macro to log to both tracing and GUI buffer
    macro_rules! log_msg {
        ($($arg:tt)*) => {{
            let msg = format!($($arg)*);
            // Log to standard CLI
            info!("{}", msg);
            // Log to GUI if attached
            if let Some(logger) = &gui_logger {
                if let Ok(mut guard) = logger.lock() {
                    guard.push_str(&msg);
                    guard.push_str(NEWLINE);
                }
            }
        }};
    }

    if args.dry_run {
        log_msg!("DRY RUN MODE: No files will be modified.");
    }

    log_msg!("Resolving IP for: {} ...", SOURCE_DNS);

    let ips = match resolve_ip(SOURCE_DNS).await {
        Ok(i) => i,
        Err(e) => {
            let err_msg = format!("Failed to resolve DNS: {}", e);
            if let Some(logger) = &gui_logger {
                if let Ok(mut guard) = logger.lock() {
                    guard.push_str(&err_msg);
                    guard.push_str(NEWLINE);
                }
            }
            return Err(eyre::eyre!(err_msg));
        }
    };

    if args.debug {
        debug!("Resolved IP list: {:?}", ips);
        if let Some(logger) = &gui_logger {
            if let Ok(mut guard) = logger.lock() {
                guard.push_str(&format!("Debug IPs: {:?}{}", ips, NEWLINE));
            }
        }
    }

    // Prefer IPv4 for compatibility
    let target_ip = ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| ips.first())
        .ok_or_else(|| eyre::eyre!("No IP address found for {}", SOURCE_DNS))?;

    log_msg!("Selected IP: {}", target_ip);

    let system_hosts_path = get_hosts_file_path();
    let input_path = args.input.as_deref().unwrap_or(&system_hosts_path);
    let output_path = args.output.as_deref().unwrap_or(input_path);

    // Call update logic
    match update_hosts_file(
        input_path,
        output_path,
        TARGET_DOMAIN,
        *target_ip,
        args.dry_run,
    )
    .await
    {
        Ok(logs) => {
            for line in logs {
                log_msg!("{}", line);
            }
            if args.dry_run {
                log_msg!("Simulation completed successfully.");
            } else {
                log_msg!("SUCCESS: Hosts file updated.");
            }
        }
        Err(e) => {
            // Check for permission errors specific to Windows/Unix
            let is_perm_error = e
                .downcast_ref::<std::io::Error>()
                .map(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                .unwrap_or(false);

            if is_perm_error {
                log_msg!("ERROR: Permission Denied!");
                if cfg!(windows) {
                    log_msg!("Please run this application as Administrator.");
                } else {
                    log_msg!("Please run using sudo.");
                }
            } else {
                log_msg!("ERROR: {}", e);
            }
            return Err(e);
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
    #[cfg(target_os = "windows")]
    {
        use winapi::um::sysinfoapi::GetSystemDirectoryW;
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        unsafe {
            const MAX_PATH: usize = 260;
            let mut buffer = [0u16; MAX_PATH];
            
            let len = GetSystemDirectoryW(buffer.as_mut_ptr(), MAX_PATH as u32) as usize;

            if len > 0 && len < MAX_PATH {
                let sys_dir = OsString::from_wide(&buffer[..len]);
                PathBuf::from(sys_dir).join("drivers").join("etc").join("hosts")
            } else {
                PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/hosts")
    }
}

async fn update_hosts_file(
    input_path: &Path,
    output_path: &Path,
    domain: &str,
    ip: IpAddr,
    dry_run: bool,
) -> Result<Vec<String>> {
    let mut logs = Vec::new();

    if !input_path.exists() {
        return Err(eyre::eyre!("Hosts file not found at {:?}", input_path));
    }

    let content = tokio::fs::read_to_string(input_path)
        .await
        .wrap_err_with(|| format!("Could not read file at {:?}", input_path))?;

    let mut new_content = String::with_capacity(content.len() + 128);
    let mut found_old = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Pass comments and empty lines through
        if trimmed.is_empty() || trimmed.starts_with('#') {
            new_content.push_str(line);
            new_content.push_str(NEWLINE);
            continue;
        }

        // Check if this line contains our target domain
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        // Standard hosts format: IP DOMAIN [ALIASES]
        let is_target_record = parts.len() >= 2 && parts[1..].contains(&domain);

        if is_target_record {
            found_old = true;
            // Don't add this line to new_content (effectively deleting it)
            // Log it though
            debug!("Removing old record: {}", line);
            continue;
        }

        new_content.push_str(line);
        new_content.push_str(NEWLINE);
    }

    if !found_old {
        debug!(
            "No existing record found for {}, appending new one.",
            domain
        );
    }

    let new_record = format!("{} {}", ip, domain);
    logs.push(format!("Writing record: {}", new_record));

    new_content.push_str(&new_record);
    new_content.push_str(NEWLINE);

    if dry_run {
        logs.push(format!("Dry run: Skipping write to {:?}", output_path));
        return Ok(logs);
    }

    tokio::fs::write(output_path, new_content)
        .await
        .wrap_err_with(|| format!("Failed to write to {:?}", output_path))?;

    Ok(logs)
}

#[cfg(target_os = "windows")]
fn is_double_clicked() -> bool {
    unsafe {
        use winapi::um::wincon::GetConsoleProcessList;
        let mut process_list: [u32; 2] = [0; 2];
        let count = GetConsoleProcessList(process_list.as_mut_ptr(), 2);
        count == 1
    }
}

#[cfg(not(target_os = "windows"))]
fn is_double_clicked() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn run_gui_mode() -> Result<()> {
    unsafe {
        use winapi::um::wincon::GetConsoleWindow;
        use winapi::um::winuser::{SW_HIDE, ShowWindow};
        let window = GetConsoleWindow();
        if !window.is_null() {
            ShowWindow(window, SW_HIDE);
        }
    }

    enable_dpi_awareness();

    // 3. Init Native Windows GUI
    nwg::init().expect("Failed to init Native Windows GUI");

    let _app = HostsApp::build_ui(Default::default()).expect("Failed to build UI");
    nwg::dispatch_thread_events();
    Ok(())
}

#[cfg(target_os = "windows")]
fn enable_dpi_awareness() {
    unsafe {
        use winapi::shared::windef::DPI_AWARENESS_CONTEXT;
        use winapi::um::winuser::SetProcessDpiAwarenessContext;

        let dpi_aware_v2 = -4isize as DPI_AWARENESS_CONTEXT;

        let _ = SetProcessDpiAwarenessContext(dpi_aware_v2);
    }
}
#[cfg(target_os = "windows")]
#[derive(Default, NwgUi)]
pub struct HostsApp {
    #[nwg_control(size: (600, 450), position: (300, 300), title: "Microsoft Store Hosts Optimizer", flags: "WINDOW|VISIBLE|RESIZABLE")]
    #[nwg_events( OnWindowClose: [HostsApp::on_exit] )]
    window: nwg::Window,

    #[nwg_layout(parent: window, spacing: 10)]
    layout: nwg::GridLayout,

    #[nwg_control(text: "Target Domain:", position: (0, 0))]
    #[nwg_layout_item(layout: layout, col: 0, row: 0)]
    label_domain: nwg::Label,

    #[nwg_control(text: TARGET_DOMAIN, readonly: true)]
    #[nwg_layout_item(layout: layout, col: 1, row: 0, col_span: 2)]
    input_domain: nwg::TextInput,

    // Row 1: Source DNS
    #[nwg_control(text: "Source DNS:", position: (0, 0))]
    #[nwg_layout_item(layout: layout, col: 0, row: 1)]
    label_dns: nwg::Label,

    #[nwg_control(text: SOURCE_DNS, readonly: true)]
    #[nwg_layout_item(layout: layout, col: 1, row: 1, col_span: 2)]
    input_dns: nwg::TextInput,

    #[nwg_control(text: "Dry Run", check_state: nwg::CheckBoxState::Unchecked)]
    #[nwg_layout_item(layout: layout, col: 1, row: 2)]
    check_dry: nwg::CheckBox,

    #[nwg_control(text: "Update Hosts File", flags: "VISIBLE")]
    #[nwg_layout_item(layout: layout, col: 1, row: 3, col_span: 2)]
    #[nwg_events( OnButtonClick: [HostsApp::on_click_update] )]
    btn_update: nwg::Button,

    #[nwg_control(text: "Ready...", flags: "VISIBLE|VSCROLL|AUTOVSCROLL", readonly: true)]
    #[nwg_layout_item(layout: layout, col: 0, row: 4, col_span: 3, row_span: 5)]
    log_box: nwg::TextBox,

    #[nwg_control]
    #[nwg_events( OnNotice: [HostsApp::on_update_complete] )]
    notice: nwg::Notice,

    logs: Arc<Mutex<String>>,
}

#[cfg(target_os = "windows")]
impl HostsApp {
    fn on_exit(&self) {
        nwg::stop_thread_dispatch();
    }

    fn on_click_update(&self) {
        // Disable button to prevent double clicks
        self.btn_update.set_enabled(false);
        self.log_box.set_text("Running...\r\n");

        // Clear previous logs
        if let Ok(mut logs) = self.logs.lock() {
            *logs = String::new();
        }

        let sender = self.notice.sender();
        let logs_handle = self.logs.clone();

        let dry_run = self.check_dry.check_state() == nwg::CheckBoxState::Checked;

        // Spawn logic in a separate thread so UI doesn't freeze
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let args = Args {
                dry_run,
                debug: true,
                input: None,
                output: None,
            };

            let res = rt.block_on(core_logic(args, Some(logs_handle.clone())));

            if let Err(e) = res {
                if let Ok(mut guard) = logs_handle.lock() {
                    guard.push_str(&format!("CRITICAL FAILURE: {:?}", e));
                }
            }

            sender.notice();
        });
    }

    fn on_update_complete(&self) {
        self.btn_update.set_enabled(true);
        if let Ok(content) = self.logs.lock() {
            self.log_box.set_text(&content);
            let len = content.len() as u32;
        }
    }
}
