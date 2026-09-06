//! ArcRelay's LAN-only browser gateway. This listener intentionally has no
//! relationship to the localhost MCP listener or its bearer-token trust model.

mod assets;
mod network_guard;
mod server;
mod session;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arcrelay_files::FileShareService;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

pub const DEFAULT_WEB_GATEWAY_PORT: u16 = 8767;

pub type Result<T> = std::result::Result<T, WebGatewayError>;

#[derive(Debug, thiserror::Error)]
pub enum WebGatewayError {
    #[error("invalid web gateway settings: {0}")]
    InvalidSettings(String),
    #[error("failed to bind web gateway to {address}: {source}")]
    Bind {
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

impl WebGatewayError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidSettings(_) => "web_gateway.invalid_settings",
            Self::Bind { .. } => "web_gateway.address_unavailable",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ts_rs::TS)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub struct WebGatewaySettings {
    pub enabled: bool,
    pub port: u16,
    pub bind_mode: WebGatewayBindMode,
    pub site_name: String,
    pub session_idle_minutes: u32,
    pub allow_vpn_private: bool,
    #[serde(skip)]
    pub allowed_hostnames: Vec<String>,
}

impl Default for WebGatewaySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_WEB_GATEWAY_PORT,
            bind_mode: WebGatewayBindMode::LanOnly,
            site_name: String::new(),
            session_idle_minutes: 720,
            allow_vpn_private: false,
            allowed_hostnames: Vec::new(),
        }
    }
}

impl WebGatewaySettings {
    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(WebGatewayError::InvalidSettings(
                "web access port must be between 1 and 65535".into(),
            ));
        }
        if !(5..=1_440).contains(&self.session_idle_minutes) {
            return Err(WebGatewayError::InvalidSettings(
                "web session idle timeout must be between 5 minutes and 24 hours".into(),
            ));
        }
        if self.site_name.len() > 128 || self.site_name.chars().any(char::is_control) {
            return Err(WebGatewayError::InvalidSettings(
                "web site name is invalid or exceeds 128 bytes".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub enum WebGatewayBindMode {
    LanOnly,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct WebGatewayStatus {
    pub enabled: bool,
    pub running: bool,
    pub port: u16,
    pub site_name: String,
    pub addresses: Vec<String>,
    pub session_count: usize,
    pub last_error: Option<String>,
}

impl Default for WebGatewayStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            running: false,
            port: DEFAULT_WEB_GATEWAY_PORT,
            site_name: String::new(),
            addresses: Vec::new(),
            session_count: 0,
            last_error: None,
        }
    }
}

struct RunningServer {
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

struct SupervisorInner {
    running: Option<RunningServer>,
}

#[derive(Clone)]
pub struct WebGatewaySupervisor {
    files: Arc<FileShareService>,
    app_version: Arc<str>,
    sessions: Arc<session::SessionStore>,
    inner: Arc<Mutex<SupervisorInner>>,
    status: Arc<RwLock<WebGatewayStatus>>,
    status_events: tokio::sync::watch::Sender<WebGatewayStatus>,
}

impl WebGatewaySupervisor {
    pub fn new(files: Arc<FileShareService>, app_version: impl Into<Arc<str>>) -> Self {
        let (status_events, _) = tokio::sync::watch::channel(WebGatewayStatus::default());
        Self {
            files,
            app_version: app_version.into(),
            sessions: Arc::new(session::SessionStore::default()),
            inner: Arc::new(Mutex::new(SupervisorInner { running: None })),
            status: Arc::new(RwLock::new(WebGatewayStatus::default())),
            status_events,
        }
    }

    pub async fn reconfigure(&self, mut settings: WebGatewaySettings) -> Result<WebGatewayStatus> {
        settings.validate()?;
        normalize_hostnames(&mut settings.allowed_hostnames);
        let mut inner = self.inner.lock().await;
        if let Some(running) = inner.running.take() {
            running.shutdown.send_replace(true);
            let mut task = running.task;
            if tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
        self.sessions.revoke_all();
        if !settings.enabled {
            let status = WebGatewayStatus {
                enabled: false,
                running: false,
                port: settings.port,
                site_name: settings.site_name,
                addresses: Vec::new(),
                session_count: 0,
                last_error: None,
            };
            *self.status.write().await = status.clone();
            self.status_events.send_replace(status.clone());
            tracing::info!(event = "web.server.stopped", "ArcRelay Web Gateway stopped");
            return Ok(status);
        }

        let address = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), settings.port);
        let listener = match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => listener,
            Err(error) => {
                let message = format!(
                    "failed to start web access: TCP port {} is unavailable ({error})",
                    settings.port
                );
                *self.status.write().await = WebGatewayStatus {
                    enabled: true,
                    running: false,
                    port: settings.port,
                    site_name: settings.site_name,
                    addresses: Vec::new(),
                    session_count: 0,
                    last_error: Some(message.clone()),
                };
                self.status_events
                    .send_replace(self.status.read().await.clone());
                return Err(WebGatewayError::Bind {
                    address,
                    source: error,
                });
            }
        };
        let ipv6_listener = bind_ipv6_listener(settings.port).await;
        let mut addresses = lan_addresses(settings.port, ipv6_listener.is_some());
        addresses.extend(
            settings
                .allowed_hostnames
                .iter()
                .filter(|hostname| hostname.ends_with(".local"))
                .map(|hostname| format!("http://{hostname}:{}", settings.port)),
        );
        addresses.sort();
        addresses.dedup();
        let status = WebGatewayStatus {
            enabled: true,
            running: true,
            port: settings.port,
            site_name: settings.site_name.clone(),
            addresses,
            session_count: 0,
            last_error: None,
        };
        *self.status.write().await = status.clone();
        self.status_events.send_replace(status.clone());
        let app = server::router(server::GatewayState::new(
            self.files.clone(),
            self.sessions.clone(),
            settings.clone(),
            self.app_version.clone(),
        ));
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let status_state = self.status.clone();
        let sessions = self.sessions.clone();
        let status_events = self.status_events.clone();
        let port = settings.port;
        let task = tokio::spawn(async move {
            tracing::info!(
                event = "web.server.started",
                port,
                "ArcRelay Web Gateway started"
            );
            let result = if let Some(ipv6_listener) = ipv6_listener {
                let ipv4 = serve_listener(listener, app.clone(), shutdown_rx.clone());
                let ipv6 = serve_listener(ipv6_listener, app, shutdown_rx);
                let (ipv4, ipv6) = tokio::join!(ipv4, ipv6);
                ipv4.and(ipv6)
            } else {
                serve_listener(listener, app, shutdown_rx).await
            };
            let mut status = status_state.write().await;
            status.running = false;
            status.session_count = sessions.len();
            if let Err(error) = result {
                status.last_error = Some(error.to_string());
                tracing::error!(event = "web.server.failed", %error, "Web Gateway stopped unexpectedly");
            }
            status_events.send_replace(status.clone());
        });
        inner.running = Some(RunningServer { shutdown, task });
        Ok(status)
    }

    pub async fn status(&self) -> WebGatewayStatus {
        let mut status = self.status.read().await.clone();
        status.session_count = self.sessions.len();
        status
    }

    pub fn subscribe_status(&self) -> tokio::sync::watch::Receiver<WebGatewayStatus> {
        self.status_events.subscribe()
    }

    pub fn revoke_sessions(&self, share_id: Option<&str>) -> usize {
        match share_id {
            Some(share_id) => self.sessions.revoke_share(share_id),
            None => self.sessions.revoke_all(),
        }
    }

    pub async fn requires_background(&self) -> bool {
        self.status.read().await.running
    }
}

fn normalize_hostnames(hostnames: &mut Vec<String>) {
    for hostname in hostnames.iter_mut() {
        *hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    }
    hostnames.retain(|hostname| !hostname.is_empty());
    hostnames.sort();
    hostnames.dedup();
}

async fn bind_ipv6_listener(port: u16) -> Option<tokio::net::TcpListener> {
    let socket = match socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    ) {
        Ok(socket) => socket,
        Err(error) => {
            tracing::debug!(%error, "IPv6 Web Gateway socket is unavailable");
            return None;
        }
    };
    if let Err(error) = socket.set_only_v6(true) {
        tracing::debug!(%error, "cannot isolate the IPv6 Web Gateway socket");
        return None;
    }
    let address = socket2::SockAddr::from(SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        port,
    ));
    if let Err(error) = socket.bind(&address) {
        tracing::warn!(%error, port, "IPv6 Web Gateway listener is unavailable; IPv4 remains active");
        return None;
    }
    if let Err(error) = socket.set_nonblocking(true) {
        tracing::warn!(%error, port, "cannot configure the IPv6 Web Gateway socket");
        return None;
    }
    match socket.listen(1024) {
        Ok(()) => {
            let listener: std::net::TcpListener = socket.into();
            match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => Some(listener),
                Err(error) => {
                    tracing::warn!(%error, port, "cannot adopt the IPv6 Web Gateway socket");
                    None
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, port, "cannot listen on the IPv6 Web Gateway socket");
            None
        }
    }
}

async fn serve_listener(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        while !*shutdown.borrow() {
            if shutdown.changed().await.is_err() {
                break;
            }
        }
    })
    .await
}

fn lan_addresses(port: u16, include_ipv6: bool) -> Vec<String> {
    let mut addresses = local_ip_address::list_afinet_netifas()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, address)| match address {
            IpAddr::V4(address)
                if network_guard::is_allowed_ipv4(address, false) && !address.is_loopback() =>
            {
                Some(format!("http://{address}:{port}"))
            }
            IpAddr::V6(address)
                if include_ipv6
                    && network_guard::is_allowed_ipv6(address)
                    && !address.is_loopback()
                    && !address.is_unicast_link_local() =>
            {
                Some(format!("http://[{address}]:{port}"))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn configured_port_conflicts_are_reported_without_scanning() {
        let occupied = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let config = tempfile::tempdir().unwrap();
        let files = FileShareService::load(config.path()).unwrap();
        let supervisor = WebGatewaySupervisor::new(files, "test");
        let error = supervisor
            .reconfigure(WebGatewaySettings {
                enabled: true,
                port,
                site_name: "Test".into(),
                ..WebGatewaySettings::default()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains(&port.to_string()));
        let status = supervisor.status().await;
        assert!(!status.running);
        assert_eq!(status.port, port);
        assert!(status.last_error.is_some());
    }
}
