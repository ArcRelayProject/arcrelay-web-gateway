use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::server::GatewayState;

pub(crate) async fn guard(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if !is_allowed_source(peer.ip(), state.settings.allow_vpn_private) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(host) = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(host_without_port)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !allowed_host(host, &state.settings.allowed_hostnames) {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        if let Some(origin) = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
        {
            let expected_http = format!(
                "http://{}",
                request.headers()[header::HOST].to_str().unwrap_or_default()
            );
            let expected_https = format!(
                "https://{}",
                request.headers()[header::HOST].to_str().unwrap_or_default()
            );
            if origin != expected_http && origin != expected_https {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
    }
    next.run(request).await
}

fn host_without_port(value: &str) -> Option<&str> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host);
    }
    Some(value.rsplit_once(':').map_or(value, |(host, _)| host))
}

fn allowed_host(host: &str, configured: &[String]) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if matches!(normalized.as_str(), "localhost" | "127.0.0.1" | "::1") {
        return true;
    }
    if configured.iter().any(|host| host == &normalized) {
        return true;
    }
    normalized
        .parse::<IpAddr>()
        .ok()
        .is_some_and(|address| local_addresses().contains(&address))
}

fn local_addresses() -> Vec<IpAddr> {
    local_ip_address::list_afinet_netifas()
        .unwrap_or_default()
        .into_iter()
        .map(|(_, address)| address)
        .collect()
}

pub(crate) fn is_allowed_source(address: IpAddr, allow_vpn_private: bool) -> bool {
    match address {
        IpAddr::V4(address) => is_allowed_ipv4(address, allow_vpn_private),
        IpAddr::V6(address) => is_allowed_ipv6(address),
    }
}

pub(crate) fn is_allowed_ipv4(address: Ipv4Addr, allow_vpn_private: bool) -> bool {
    address.is_loopback()
        || address.is_private()
        || (allow_vpn_private
            && address.octets()[0] == 100
            && (64..=127).contains(&address.octets()[1]))
        || address.is_link_local()
}

pub(crate) fn is_allowed_ipv6(address: Ipv6Addr) -> bool {
    address.is_loopback()
        || address.is_unicast_link_local()
        || (address.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_public_sources_and_cgnat_by_default() {
        assert!(is_allowed_source("192.168.1.8".parse().unwrap(), false));
        assert!(!is_allowed_source("8.8.8.8".parse().unwrap(), false));
        assert!(!is_allowed_source("100.64.1.2".parse().unwrap(), false));
        assert!(is_allowed_source("100.64.1.2".parse().unwrap(), true));
        assert!(is_allowed_source("fd12::1".parse().unwrap(), false));
    }
}
