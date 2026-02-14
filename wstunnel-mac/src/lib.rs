// wstunnel-mac: C FFI wrapper for wstunnel (macOS)
//
// Wraps wstunnel identically to wstunnel-cli: constructs the same Client
// config struct and calls run_client() with a JoinSetTokioExecutor.
//
// Usage:
//   1. (Optional) Set a log callback with wstunnel_set_log_callback()
//   2. Initialize logging with wstunnel_init_logging()
//   3. Create a config with wstunnel_config_new()
//   4. Set remote URL, tunnels, and options
//   5. Start with wstunnel_client_start(config)
//   6. Stop with wstunnel_client_stop()

use std::ffi::{CStr, CString};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::raw::c_char;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls_pki_types::DnsName;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use url::{Host, Url};

use tracing_core::field::Visit;
use tracing_core::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

// Import types from wstunnel — exactly the same types the CLI uses
use wstunnel::config::{Client, HeaderName, HeaderValue, LocalToRemote};
use wstunnel::executor::JoinSetTokioExecutor;
use wstunnel::tunnel::LocalProtocol;

// ═══════════════════════════════════════════════════════════════
// Constants (match wstunnel-cli defaults)
// ═══════════════════════════════════════════════════════════════

pub const WS_OK: i32 = 0;
pub const WS_ERR_ALREADY_RUNNING: i32 = -1;
pub const WS_ERR_INVALID_PARAM: i32 = -2;
pub const WS_ERR_RUNTIME: i32 = -3;
pub const WS_ERR_START_FAILED: i32 = -4;
pub const WS_ERR_NOT_RUNNING: i32 = -5;
pub const WS_ERR_CONFIG_NULL: i32 = -6;

pub const WS_LOG_ERROR: i32 = 0;
pub const WS_LOG_WARN: i32 = 1;
pub const WS_LOG_INFO: i32 = 2;
pub const WS_LOG_DEBUG: i32 = 3;
pub const WS_LOG_TRACE: i32 = 4;

// ═══════════════════════════════════════════════════════════════
// Global State
// ═══════════════════════════════════════════════════════════════

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static RUNNING: AtomicBool = AtomicBool::new(false);
static STOP_TX: Mutex<Option<oneshot::Sender<()>>> = Mutex::new(None);
static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);

/// Log callback: (level, message, user_context)
type LogCallbackFn = unsafe extern "C" fn(i32, *const c_char, *mut std::ffi::c_void);

/// Wrapper to make *mut c_void Send+Sync for use in static Mutex.
/// Safety: the pointer is only passed back to the C callback on the same thread model.
struct SendPtr(*mut std::ffi::c_void);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

static LOG_CALLBACK: Mutex<Option<LogCallbackFn>> = Mutex::new(None);
static LOG_CONTEXT: Mutex<SendPtr> = Mutex::new(SendPtr(std::ptr::null_mut()));

// ═══════════════════════════════════════════════════════════════
// Config Builder (FFI-friendly, converts to Client at start time)
// ═══════════════════════════════════════════════════════════════

/// Opaque config handle for C API.
/// Mirrors wstunnel::config::Client fields using C-compatible types.
pub struct WstunnelConfig {
    // Required
    remote_url: Option<String>,

    // Tunnel rules
    tunnels: Vec<TunnelRule>,

    // Connection / path
    http_upgrade_path_prefix: String,
    http_upgrade_credentials: Option<String>, // "USER:PASS" → Basic auth
    connection_min_idle: u32,
    connection_retry_max_backoff_secs: u64,

    // WebSocket
    websocket_ping_frequency_secs: Option<u32>, // None = use default 30s
    websocket_mask_frame: bool,

    // TLS
    tls_verify_certificate: bool,
    tls_sni_override: Option<String>,
    tls_sni_disable: bool,

    // HTTP headers
    http_headers: Vec<(String, String)>,

    // Proxy
    http_proxy: Option<String>,
    http_proxy_login: Option<String>,
    http_proxy_password: Option<String>,

    // Runtime
    worker_threads: usize,
}

#[derive(Clone)]
enum TunnelRule {
    Udp {
        local_host: String,
        local_port: u16,
        remote_host: String,
        remote_port: u16,
        timeout_secs: Option<u64>,
    },
    Tcp {
        local_host: String,
        local_port: u16,
        remote_host: String,
        remote_port: u16,
        proxy_protocol: bool,
    },
    Socks5 {
        local_host: String,
        local_port: u16,
        timeout_secs: Option<u64>,
        login: Option<String>,
        password: Option<String>,
    },
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok().map(|s| s.to_string())
}

fn set_last_error(msg: &str) {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = CString::new(msg).ok();
    }
    emit_log(WS_LOG_ERROR, msg);
}

fn emit_log(level: i32, message: &str) {
    let cb = LOG_CALLBACK.lock().ok().and_then(|g| *g);
    if let Some(callback) = cb {
        let ctx = LOG_CONTEXT.lock().ok().map(|g| g.0).unwrap_or(std::ptr::null_mut());
        if let Ok(cmsg) = CString::new(message) {
            unsafe { callback(level, cmsg.as_ptr(), ctx) };
        }
    }
}

fn get_or_init_runtime(worker_threads: usize) -> Option<&'static Runtime> {
    if let Some(rt) = RUNTIME.get() {
        return Some(rt);
    }
    let threads = if worker_threads == 0 { 2 } else { worker_threads };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .thread_name("wstunnel-mac")
        .build()
        .ok()?;
    let _ = RUNTIME.set(rt);
    RUNTIME.get()
}

/// Convert FFI config into the exact same Client struct that wstunnel-cli builds
fn build_client_config(config: &WstunnelConfig) -> Result<Client, String> {
    // Parse remote URL
    let remote_addr = config.remote_url.as_ref()
        .ok_or("Remote URL not set")?;
    let remote_addr = Url::parse(remote_addr)
        .map_err(|e| format!("Invalid remote URL: {}", e))?;

    // Build tunnel rules → LocalToRemote (same as CLI -L flag parsing)
    let mut local_to_remote = Vec::new();
    for rule in &config.tunnels {
        match rule {
            TunnelRule::Udp { local_host, local_port, remote_host, remote_port, timeout_secs } => {
                let local_ip = Ipv4Addr::from_str(local_host)
                    .map_err(|e| format!("Invalid local host '{}': {}", local_host, e))?;
                let dest_host = Host::parse(remote_host)
                    .map_err(|e| format!("Invalid remote host '{}': {}", remote_host, e))?;
                local_to_remote.push(LocalToRemote {
                    local_protocol: LocalProtocol::Udp {
                        timeout: timeout_secs.map(Duration::from_secs),
                    },
                    local: SocketAddr::V4(SocketAddrV4::new(local_ip, *local_port)),
                    remote: (dest_host, *remote_port),
                });
            }
            TunnelRule::Tcp { local_host, local_port, remote_host, remote_port, proxy_protocol } => {
                let local_ip = Ipv4Addr::from_str(local_host)
                    .map_err(|e| format!("Invalid local host '{}': {}", local_host, e))?;
                let dest_host = Host::parse(remote_host)
                    .map_err(|e| format!("Invalid remote host '{}': {}", remote_host, e))?;
                local_to_remote.push(LocalToRemote {
                    local_protocol: LocalProtocol::Tcp {
                        proxy_protocol: *proxy_protocol,
                    },
                    local: SocketAddr::V4(SocketAddrV4::new(local_ip, *local_port)),
                    remote: (dest_host, *remote_port),
                });
            }
            TunnelRule::Socks5 { local_host, local_port, timeout_secs, login, password } => {
                let local_ip = Ipv4Addr::from_str(local_host)
                    .map_err(|e| format!("Invalid local host '{}': {}", local_host, e))?;
                let credentials = match (login, password) {
                    (Some(l), Some(p)) => Some((l.clone(), p.clone())),
                    _ => None,
                };
                local_to_remote.push(LocalToRemote {
                    local_protocol: LocalProtocol::Socks5 {
                        timeout: timeout_secs.map(Duration::from_secs),
                        credentials,
                    },
                    local: SocketAddr::V4(SocketAddrV4::new(local_ip, *local_port)),
                    // socks5 is dynamic — remote is placeholder
                    remote: (Host::Ipv4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                });
            }
        }
    }

    // TLS SNI override
    let tls_sni_override = match &config.tls_sni_override {
        Some(domain) => {
            let name = DnsName::try_from(domain.as_str())
                .map_err(|e| format!("Invalid SNI domain '{}': {}", domain, e))?;
            Some(name.to_owned())
        }
        None => None,
    };

    // HTTP upgrade credentials (USER:PASS → Basic auth HeaderValue)
    let http_upgrade_credentials = config.http_upgrade_credentials.as_ref().map(|creds| {
        let encoded = BASE64.encode(creds.as_bytes());
        HeaderValue::from_str(&format!("Basic {}", encoded))
            .unwrap_or_else(|_| HeaderValue::from_static(""))
    });

    // WebSocket ping frequency — matches CLI default of 30s
    let websocket_ping_frequency = match config.websocket_ping_frequency_secs {
        Some(0) => None,                           // 0 = disabled
        Some(s) => Some(Duration::from_secs(s as u64)),
        None => Some(Duration::from_secs(30)),     // default like CLI
    };

    // HTTP headers
    let http_headers: Vec<(HeaderName, HeaderValue)> = config.http_headers.iter()
        .filter_map(|(name, value)| {
            let hn = HeaderName::from_str(name).ok()?;
            let hv = HeaderValue::from_str(value).ok()?;
            Some((hn, hv))
        })
        .collect();

    // Build the exact same Client struct that wstunnel-cli/main.rs creates
    Ok(Client {
        local_to_remote,
        remote_to_local: vec![],
        socket_so_mark: None,
        connection_min_idle: config.connection_min_idle,
        connection_retry_max_backoff: Duration::from_secs(config.connection_retry_max_backoff_secs),
        reverse_tunnel_connection_retry_max_backoff: Duration::from_secs(1),
        tls_sni_override,
        tls_sni_disable: config.tls_sni_disable,
        tls_ech_enable: false,
        tls_verify_certificate: config.tls_verify_certificate,
        http_proxy: config.http_proxy.clone(),
        http_proxy_login: config.http_proxy_login.clone(),
        http_proxy_password: config.http_proxy_password.clone(),
        http_upgrade_path_prefix: config.http_upgrade_path_prefix.clone(),
        http_upgrade_credentials,
        websocket_ping_frequency,
        websocket_mask_frame: config.websocket_mask_frame,
        http_headers,
        http_headers_file: None,
        remote_addr,
        tls_certificate: None,
        tls_private_key: None,
        dns_resolver: vec![],
        dns_resolver_prefer_ipv4: false,
    })
}

// ═══════════════════════════════════════════════════════════════
// Custom Tracing Layer (bridges tracing → C callback)
// ═══════════════════════════════════════════════════════════════

struct CallbackLayer;

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for CallbackLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let cb = LOG_CALLBACK.lock().ok().and_then(|g| *g);
        if cb.is_none() {
            return;
        }

        let level = match *event.metadata().level() {
            tracing::Level::ERROR => WS_LOG_ERROR,
            tracing::Level::WARN => WS_LOG_WARN,
            tracing::Level::INFO => WS_LOG_INFO,
            tracing::Level::DEBUG => WS_LOG_DEBUG,
            tracing::Level::TRACE => WS_LOG_TRACE,
        };

        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        emit_log(level, &visitor.0);
    }
}

struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing_core::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        } else if !self.0.is_empty() {
            self.0.push_str(&format!(" {}={:?}", field.name(), value));
        } else {
            self.0 = format!("{}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &tracing_core::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        } else if !self.0.is_empty() {
            self.0.push_str(&format!(" {}={}", field.name(), value));
        } else {
            self.0 = format!("{}={}", field.name(), value);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Public FFI: Logging
// ═══════════════════════════════════════════════════════════════

/// Set a callback to receive all wstunnel log messages.
/// Call BEFORE wstunnel_init_logging().
///
/// callback: function pointer (level, message, context)
/// context:  opaque pointer passed back to callback (can be NULL)
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_set_log_callback(
    callback: Option<unsafe extern "C" fn(i32, *const c_char, *mut std::ffi::c_void)>,
    context: *mut std::ffi::c_void,
) {
    if let Ok(mut guard) = LOG_CALLBACK.lock() {
        *guard = callback;
    }
    if let Ok(mut guard) = LOG_CONTEXT.lock() {
        *guard = SendPtr(context);
    }
}

/// Initialize the logging subsystem. Call once at app startup.
/// Uses the same EnvFilter as wstunnel-cli.
///
/// log_level: 0=error, 1=warn, 2=info, 3=debug, 4=trace
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_init_logging(log_level: i32) {
    let filter = match log_level {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };

    // Suppress noisy h2 codec logs (same as CLI)
    let filter_str = format!("{},h2::codec=off", filter);

    let has_callback = LOG_CALLBACK.lock().ok().and_then(|g| *g).is_some();

    if has_callback {
        use tracing_subscriber::prelude::*;
        let filter_layer = tracing_subscriber::EnvFilter::new(&filter_str);
        let _ = tracing_subscriber::registry()
            .with(filter_layer)
            .with(CallbackLayer)
            .try_init();
    } else {
        // Default: log to stderr (same as CLI)
        let _ = tracing_subscriber::fmt()
            .with_env_filter(&filter_str)
            .with_target(false)
            .try_init();
    }
}

// ═══════════════════════════════════════════════════════════════
// Public FFI: Config Builder
// ═══════════════════════════════════════════════════════════════

/// Create a new config builder. Must be freed with wstunnel_config_free().
/// Defaults match wstunnel-cli defaults.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_new() -> *mut WstunnelConfig {
    let config = Box::new(WstunnelConfig {
        remote_url: None,
        tunnels: Vec::new(),
        http_upgrade_path_prefix: "v1".to_string(), // CLI default
        http_upgrade_credentials: None,
        connection_min_idle: 0,
        connection_retry_max_backoff_secs: 300, // 5 minutes, CLI default
        websocket_ping_frequency_secs: None,    // None = use default 30s
        websocket_mask_frame: false,
        tls_verify_certificate: false,
        tls_sni_override: None,
        tls_sni_disable: false,
        http_headers: Vec::new(),
        http_proxy: None,
        http_proxy_login: None,
        http_proxy_password: None,
        worker_threads: 2,
    });
    Box::into_raw(config)
}

/// Free a config builder.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_free(config: *mut WstunnelConfig) {
    if !config.is_null() {
        unsafe { drop(Box::from_raw(config)) };
    }
}

/// Set the remote wstunnel server URL (e.g. "wss://example.com:443").
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_remote_url(
    config: *mut WstunnelConfig,
    url: *const c_char,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    match unsafe { cstr_to_string(url) } {
        Some(s) => { config.remote_url = Some(s); WS_OK }
        None => WS_ERR_INVALID_PARAM,
    }
}

/// Set the HTTP upgrade path prefix.
/// This is the "secret" path in Ghost Mode, or the default "v1" for standard setups.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_http_upgrade_path_prefix(
    config: *mut WstunnelConfig,
    prefix: *const c_char,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    match unsafe { cstr_to_string(prefix) } {
        Some(s) => { config.http_upgrade_path_prefix = s; WS_OK }
        None => WS_ERR_INVALID_PARAM,
    }
}

/// Set HTTP upgrade credentials (Basic auth). Format: "USER:PASS"
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_http_upgrade_credentials(
    config: *mut WstunnelConfig,
    credentials: *const c_char,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    match unsafe { cstr_to_string(credentials) } {
        Some(s) => { config.http_upgrade_credentials = Some(s); WS_OK }
        None => WS_ERR_INVALID_PARAM,
    }
}

/// Enable/disable TLS certificate verification (default: false).
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_tls_verify(
    config: *mut WstunnelConfig,
    verify: bool,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    config.tls_verify_certificate = verify;
    WS_OK
}

/// Override the TLS SNI domain name.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_tls_sni_override(
    config: *mut WstunnelConfig,
    domain: *const c_char,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    match unsafe { cstr_to_string(domain) } {
        Some(s) => { config.tls_sni_override = Some(s); WS_OK }
        None => WS_ERR_INVALID_PARAM,
    }
}

/// Disable sending SNI during TLS handshake.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_tls_sni_disable(
    config: *mut WstunnelConfig,
    disable: bool,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    config.tls_sni_disable = disable;
    WS_OK
}

/// Set WebSocket ping frequency in seconds (default: 30, 0 to disable).
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_websocket_ping_frequency(
    config: *mut WstunnelConfig,
    secs: u32,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    config.websocket_ping_frequency_secs = Some(secs);
    WS_OK
}

/// Enable WebSocket frame masking (default: false).
/// Only needed for non-TLS connections with misbehaving proxies.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_websocket_mask_frame(
    config: *mut WstunnelConfig,
    mask: bool,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    config.websocket_mask_frame = mask;
    WS_OK
}

/// Set minimum idle connections in the pool (default: 0).
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_connection_min_idle(
    config: *mut WstunnelConfig,
    count: u32,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    config.connection_min_idle = count;
    WS_OK
}

/// Set maximum connection retry backoff in seconds (default: 300 = 5 minutes).
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_connection_retry_max_backoff(
    config: *mut WstunnelConfig,
    secs: u64,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    config.connection_retry_max_backoff_secs = secs;
    WS_OK
}

/// Set an HTTP proxy for connecting to the wstunnel server.
/// Format: "HOST:PORT" or "http://HOST:PORT"
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_http_proxy(
    config: *mut WstunnelConfig,
    proxy: *const c_char,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    match unsafe { cstr_to_string(proxy) } {
        Some(s) => { config.http_proxy = Some(s); WS_OK }
        None => WS_ERR_INVALID_PARAM,
    }
}

/// Add a custom HTTP header to the upgrade request.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_add_http_header(
    config: *mut WstunnelConfig,
    name: *const c_char,
    value: *const c_char,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    let n = match unsafe { cstr_to_string(name) } {
        Some(s) => s,
        None => return WS_ERR_INVALID_PARAM,
    };
    let v = match unsafe { cstr_to_string(value) } {
        Some(s) => s,
        None => return WS_ERR_INVALID_PARAM,
    };
    config.http_headers.push((n, v));
    WS_OK
}

/// Set the number of Tokio worker threads (default: 2).
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_set_worker_threads(
    config: *mut WstunnelConfig,
    threads: u32,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    config.worker_threads = threads as usize;
    WS_OK
}

// ─── Tunnel Rules ────────────────────────────────────────────

/// Add a UDP tunnel rule: local_host:local_port → remote_host:remote_port
/// Equivalent to CLI: -L udp://local_host:local_port:remote_host:remote_port
/// timeout_secs: UDP session timeout (0 = default 30s from wstunnel)
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_add_tunnel_udp(
    config: *mut WstunnelConfig,
    local_host: *const c_char,
    local_port: u16,
    remote_host: *const c_char,
    remote_port: u16,
    timeout_secs: u64,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    let lh = match unsafe { cstr_to_string(local_host) } {
        Some(s) => s,
        None => return WS_ERR_INVALID_PARAM,
    };
    let rh = match unsafe { cstr_to_string(remote_host) } {
        Some(s) => s,
        None => return WS_ERR_INVALID_PARAM,
    };
    config.tunnels.push(TunnelRule::Udp {
        local_host: lh,
        local_port,
        remote_host: rh,
        remote_port,
        timeout_secs: if timeout_secs == 0 { None } else { Some(timeout_secs) },
    });
    WS_OK
}

/// Add a TCP tunnel rule: local_host:local_port → remote_host:remote_port
/// Equivalent to CLI: -L tcp://local_host:local_port:remote_host:remote_port
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_add_tunnel_tcp(
    config: *mut WstunnelConfig,
    local_host: *const c_char,
    local_port: u16,
    remote_host: *const c_char,
    remote_port: u16,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    let lh = match unsafe { cstr_to_string(local_host) } {
        Some(s) => s,
        None => return WS_ERR_INVALID_PARAM,
    };
    let rh = match unsafe { cstr_to_string(remote_host) } {
        Some(s) => s,
        None => return WS_ERR_INVALID_PARAM,
    };
    config.tunnels.push(TunnelRule::Tcp {
        local_host: lh,
        local_port,
        remote_host: rh,
        remote_port,
        proxy_protocol: false,
    });
    WS_OK
}

/// Add a SOCKS5 proxy listener on local_host:local_port
/// Equivalent to CLI: -L socks5://local_host:local_port
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_config_add_tunnel_socks5(
    config: *mut WstunnelConfig,
    local_host: *const c_char,
    local_port: u16,
    timeout_secs: u64,
) -> i32 {
    let config = match unsafe { config.as_mut() } {
        Some(c) => c,
        None => return WS_ERR_CONFIG_NULL,
    };
    let lh = match unsafe { cstr_to_string(local_host) } {
        Some(s) => s,
        None => return WS_ERR_INVALID_PARAM,
    };
    config.tunnels.push(TunnelRule::Socks5 {
        local_host: lh,
        local_port,
        timeout_secs: if timeout_secs == 0 { None } else { Some(timeout_secs) },
        login: None,
        password: None,
    });
    WS_OK
}

// ═══════════════════════════════════════════════════════════════
// Public FFI: Client Control
// ═══════════════════════════════════════════════════════════════

/// Start the wstunnel client with the given config.
/// Internally builds a wstunnel::config::Client and calls wstunnel::run_client()
/// exactly as wstunnel-cli does.
///
/// The config is NOT consumed — call wstunnel_config_free() after start.
/// Returns: WS_OK on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_client_start(config: *mut WstunnelConfig) -> i32 {
    if RUNNING.load(Ordering::SeqCst) {
        set_last_error("Client is already running");
        return WS_ERR_ALREADY_RUNNING;
    }

    let config = match unsafe { config.as_ref() } {
        Some(c) => c,
        None => {
            set_last_error("Config is null");
            return WS_ERR_CONFIG_NULL;
        }
    };

    if config.tunnels.is_empty() {
        set_last_error("No tunnel rules configured");
        return WS_ERR_INVALID_PARAM;
    }

    // Build the same Client struct that wstunnel-cli creates from CLI args
    let client_config = match build_client_config(config) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&e);
            return WS_ERR_INVALID_PARAM;
        }
    };

    let runtime = match get_or_init_runtime(config.worker_threads) {
        Some(rt) => rt,
        None => {
            set_last_error("Failed to create Tokio runtime");
            return WS_ERR_RUNTIME;
        }
    };

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    {
        let mut guard = STOP_TX.lock().unwrap();
        *guard = Some(stop_tx);
    }

    let remote_url_str = config.remote_url.as_deref().unwrap_or("unknown").to_string();
    RUNNING.store(true, Ordering::SeqCst);
    emit_log(WS_LOG_INFO, &format!("Starting wstunnel client → {}", remote_url_str));

    // Run client exactly like CLI: run_client(config, executor)
    // JoinSetTokioExecutor allows clean abort on stop (unlike DefaultTokioExecutor)
    runtime.spawn(async move {
        let executor = JoinSetTokioExecutor::default();

        tokio::select! {
            result = wstunnel::run_client(client_config, executor) => {
                match result {
                    Ok(()) => emit_log(WS_LOG_INFO, "wstunnel client exited normally"),
                    Err(e) => {
                        let msg = format!("wstunnel client error: {:?}", e);
                        emit_log(WS_LOG_ERROR, &msg);
                        if let Ok(mut guard) = LAST_ERROR.lock() {
                            *guard = CString::new(msg).ok();
                        }
                    }
                }
            }
            _ = stop_rx => {
                emit_log(WS_LOG_INFO, "wstunnel client stopped by request");
            }
        }

        RUNNING.store(false, Ordering::SeqCst);
    });

    WS_OK
}

/// Stop the running wstunnel client.
///
/// Returns: WS_OK on success, WS_ERR_NOT_RUNNING if not active.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_client_stop() -> i32 {
    if !RUNNING.load(Ordering::SeqCst) {
        return WS_ERR_NOT_RUNNING;
    }

    let tx = {
        let mut guard = STOP_TX.lock().unwrap();
        guard.take()
    };

    match tx {
        Some(sender) => {
            let _ = sender.send(());
            // Give executor time to abort tasks
            std::thread::sleep(Duration::from_millis(100));
            RUNNING.store(false, Ordering::SeqCst);
            emit_log(WS_LOG_INFO, "wstunnel client stop requested");
            WS_OK
        }
        None => WS_ERR_NOT_RUNNING,
    }
}

/// Check if the wstunnel client is running.
///
/// Returns: 1 if running, 0 if not.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_client_is_running() -> i32 {
    if RUNNING.load(Ordering::SeqCst) { 1 } else { 0 }
}

/// Get the last error message, or NULL if no error.
///
/// The returned pointer is valid until the next error occurs.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_client_get_last_error() -> *const c_char {
    match LAST_ERROR.lock() {
        Ok(guard) => match &*guard {
            Some(cstr) => cstr.as_ptr(),
            None => std::ptr::null(),
        },
        Err(_) => std::ptr::null(),
    }
}

/// Get the wstunnel library version string.
#[unsafe(no_mangle)]
pub extern "C" fn wstunnel_get_version() -> *const c_char {
    // Match the actual wstunnel crate version
    c"10.5.2".as_ptr()
}
