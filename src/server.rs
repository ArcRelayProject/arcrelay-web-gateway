use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arcrelay_files::{
    FileShareService, PreviewKind, SharedDirectory, WebAccessMode, DEFAULT_DIRECTORY_PAGE_SIZE,
    MAX_TEXT_PREVIEW_BYTES,
};
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use tokio_util::io::ReaderStream;

use crate::session::SessionStore;
use crate::WebGatewaySettings;

const SESSION_COOKIE: &str = "arcrelay_web_session";
const MAX_FAILED_ATTEMPTS_PER_MINUTE: usize = 5;
const MAX_CONCURRENT_STREAMS: usize = 16;
const MAX_CONCURRENT_STREAMS_PER_IP: usize = 4;
type FailedAuthAttempts = Arc<Mutex<HashMap<(IpAddr, String), VecDeque<Instant>>>>;

#[derive(Clone)]
pub(crate) struct GatewayState {
    pub files: Arc<FileShareService>,
    pub sessions: Arc<SessionStore>,
    pub settings: Arc<WebGatewaySettings>,
    app_version: Arc<str>,
    failed_auth: FailedAuthAttempts,
    stream_limit: Arc<tokio::sync::Semaphore>,
    per_ip_stream_limits: Arc<Mutex<HashMap<IpAddr, Arc<tokio::sync::Semaphore>>>>,
}

impl GatewayState {
    pub fn new(
        files: Arc<FileShareService>,
        sessions: Arc<SessionStore>,
        settings: WebGatewaySettings,
        app_version: Arc<str>,
    ) -> Self {
        Self {
            files,
            sessions,
            settings: Arc::new(settings),
            app_version,
            failed_auth: Arc::new(Mutex::new(HashMap::new())),
            stream_limit: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STREAMS)),
            per_ip_stream_limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn idle_lifetime(&self) -> Duration {
        Duration::from_secs(u64::from(self.settings.session_idle_minutes) * 60)
    }
}

pub(crate) fn router(state: GatewayState) -> Router {
    Router::new()
        .route("/api/v1/site", get(site))
        .route("/api/v1/shares", get(shares))
        .route("/api/v1/shares/{slug}/unlock", post(unlock))
        .route("/api/v1/shares/{slug}/lock", post(lock))
        .route("/api/v1/shares/{slug}/entries", get(entries))
        .route("/api/v1/shares/{slug}/metadata", get(metadata))
        .route("/api/v1/shares/{slug}/text", get(text_preview))
        .route("/api/v1/shares/{slug}/thumbnail", get(thumbnail))
        .route("/api/v1/shares/{slug}/content", get(content).head(content))
        .route("/api/v1/session/logout", post(logout))
        .fallback(static_asset)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::network_guard::guard,
        ))
        .with_state(state)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SiteView {
    site_name: String,
    version: String,
    files_enabled: bool,
}

async fn site(State(state): State<GatewayState>) -> Json<SiteView> {
    Json(SiteView {
        site_name: state.settings.site_name.clone(),
        version: state.app_version.to_string(),
        files_enabled: true,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShareView {
    name: String,
    slug: String,
    mode: WebAccessMode,
    unlocked: bool,
    allow_preview: bool,
    allow_download: bool,
}

async fn shares(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Json<Vec<ShareView>> {
    let token = session_cookie(&headers);
    Json(
        state
            .files
            .listed_web_shares()
            .into_iter()
            .map(|share| share_view(&state, &share, token.as_deref(), peer.ip()))
            .collect(),
    )
}

fn share_view(
    state: &GatewayState,
    share: &SharedDirectory,
    token: Option<&str>,
    source_ip: IpAddr,
) -> ShareView {
    ShareView {
        name: share.name.clone(),
        slug: share.web.slug.clone(),
        mode: share.web.mode,
        unlocked: share.web.mode == WebAccessMode::Public
            || state.sessions.authorized(
                token,
                source_ip,
                &share.id,
                share.web.credential_revision,
                state.idle_lifetime(),
            ),
        allow_preview: share.web.allow_preview,
        allow_download: share.web.allow_download,
    }
}

#[derive(Deserialize)]
struct UnlockRequest {
    password: String,
}

async fn unlock(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UnlockRequest>,
) -> Result<Response, ApiError> {
    let Some(share) = state.files.web_share_by_slug(&slug) else {
        tracing::warn!(
            event = "web.auth.failed",
            source_address_family = address_family(peer.ip()),
            reason = "unavailable"
        );
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "password is incorrect or the share is unavailable",
        ));
    };
    if share.web.mode != WebAccessMode::Password {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "password is incorrect or the share is unavailable",
        ));
    }
    if auth_rate_limited(&state, peer.ip(), &share.id) {
        tracing::warn!(
            event = "web.auth.failed",
            source_address_family = address_family(peer.ip()),
            reason = "rate_limited"
        );
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts; try again later",
        ));
    }
    let files = state.files.clone();
    let verify_slug = slug.clone();
    let verified = tokio::task::spawn_blocking(move || {
        files.verify_web_password(&verify_slug, &body.password)
    })
    .await
    .map_err(ApiError::internal_with)?;
    let Some((share_id, revision)) = verified else {
        record_auth_failure(&state, peer.ip(), &share.id);
        tracing::warn!(
            event = "web.auth.failed",
            source_address_family = address_family(peer.ip())
        );
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "password is incorrect or the share is unavailable",
        ));
    };
    clear_auth_failures(&state, peer.ip(), &share.id);
    let existing = session_cookie(&headers);
    let token = state.sessions.create_or_authorize(
        existing.as_deref(),
        peer.ip(),
        &share_id,
        revision,
        state.idle_lifetime(),
    );
    tracing::info!(
        event = "web.auth.succeeded",
        source_address_family = address_family(peer.ip())
    );
    let mut response = Json(serde_json::json!({ "unlocked": true })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400"
        ))
        .map_err(ApiError::internal_with)?,
    );
    Ok(response)
}

async fn lock(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let share = state
        .files
        .web_share_by_slug(&slug)
        .ok_or_else(ApiError::not_found)?;
    state
        .sessions
        .lock_share(session_cookie(&headers).as_deref(), &share.id);
    tracing::info!(
        event = "web.session.revoked",
        source_address_family = address_family(peer.ip())
    );
    Ok(Json(serde_json::json!({ "locked": true })))
}

async fn logout(State(state): State<GatewayState>, headers: HeaderMap) -> Response {
    state.sessions.logout(session_cookie(&headers).as_deref());
    let mut response = Json(serde_json::json!({ "loggedOut": true })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "arcrelay_web_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    response
}

#[derive(Deserialize)]
struct BrowseQuery {
    #[serde(default)]
    path: String,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn entries(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(slug): Path<String>,
    Query(query): Query<BrowseQuery>,
    headers: HeaderMap,
) -> Result<Json<arcrelay_files::DirectoryPage>, ApiError> {
    let share = authorized_share(&state, &headers, peer.ip(), &slug)?;
    let page = state
        .files
        .list_web_directory_page(
            &share.id,
            &query.path,
            query.cursor.as_deref(),
            query.limit.unwrap_or(DEFAULT_DIRECTORY_PAGE_SIZE),
        )
        .await
        .map_err(ApiError::bad_request)?;
    tracing::info!(
        event = "web.share.opened",
        source_address_family = address_family(peer.ip()),
        path_depth = relative_path_depth(&query.path)
    );
    Ok(Json(page))
}

#[derive(Deserialize)]
struct FileQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    download: bool,
    dimension: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MetadataView {
    share: ShareView,
    entry: Option<arcrelay_files::FileEntry>,
}

async fn metadata(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(slug): Path<String>,
    Query(query): Query<FileQuery>,
    headers: HeaderMap,
) -> Result<Json<MetadataView>, ApiError> {
    let share = state
        .files
        .web_share_by_slug(&slug)
        .ok_or_else(ApiError::not_found)?;
    let entry = if query.path.is_empty() {
        None
    } else {
        let share = authorized_share(&state, &headers, peer.ip(), &slug)?;
        Some(
            state
                .files
                .prepare_file(&share.id, &query.path, true)
                .await
                .map_err(ApiError::bad_request)?
                .entry,
        )
    };
    Ok(Json(MetadataView {
        share: share_view(
            &state,
            &share,
            session_cookie(&headers).as_deref(),
            peer.ip(),
        ),
        entry,
    }))
}

async fn text_preview(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(slug): Path<String>,
    Query(query): Query<FileQuery>,
    headers: HeaderMap,
) -> Result<Json<arcrelay_files::TextPreview>, ApiError> {
    let share = authorized_share(&state, &headers, peer.ip(), &slug)?;
    if !share.web.allow_preview {
        return Err(ApiError::forbidden());
    }
    let preview = state
        .files
        .text_preview(
            &share.id,
            &query.path,
            MAX_TEXT_PREVIEW_BYTES.min(512 * 1024),
        )
        .await
        .map_err(ApiError::bad_request)?;
    tracing::info!(
        event = "web.file.previewed",
        source_address_family = address_family(peer.ip()),
        path_depth = relative_path_depth(&query.path)
    );
    Ok(Json(preview))
}

async fn thumbnail(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(slug): Path<String>,
    Query(query): Query<FileQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let share = authorized_share(&state, &headers, peer.ip(), &slug)?;
    if !share.web.allow_preview {
        return Err(ApiError::forbidden());
    }
    let thumbnail = state
        .files
        .prepare_thumbnail(&share.id, &query.path, query.dimension.unwrap_or(512), true)
        .await
        .map_err(ApiError::bad_request)?
        .ok_or_else(ApiError::not_found)?;
    let mut response = thumbnail.bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&thumbnail.media_type).map_err(ApiError::internal_with)?,
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=300"),
    );
    Ok(response)
}

async fn content(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(slug): Path<String>,
    Query(query): Query<FileQuery>,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, ApiError> {
    let share = authorized_share(&state, &headers, peer.ip(), &slug)?;
    let prepared = state
        .files
        .prepare_file(&share.id, &query.path, true)
        .await
        .map_err(ApiError::bad_request)?;
    let inline = share.web.allow_preview
        && matches!(
            prepared.entry.preview_kind,
            PreviewKind::Image | PreviewKind::Audio | PreviewKind::Video
        );
    if query.download && !share.web.allow_download {
        return Err(ApiError::forbidden());
    }
    if !inline && !share.web.allow_download {
        return Err(ApiError::forbidden());
    }
    let metadata = tokio::fs::metadata(&prepared.path)
        .await
        .map_err(|_| ApiError::not_found())?;
    let total = metadata.len();
    let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
    let etag = format!("\"{:x}-{:x}\"", total, prepared.entry.modified_at_ms);
    let range = if if_range_matches(&headers, &etag, modified) {
        parse_range(headers.get(header::RANGE), total)?
    } else {
        None
    };
    let (start, end, status) = match range {
        Some(range) => (*range.start(), *range.end(), StatusCode::PARTIAL_CONTENT),
        None => (0, total.saturating_sub(1), StatusCode::OK),
    };
    let content_length = if total == 0 { 0 } else { end - start + 1 };
    let disposition = if query.download || !inline {
        "attachment"
    } else {
        "inline"
    };
    let encoded_name = utf8_percent_encode(&prepared.entry.name, NON_ALPHANUMERIC).to_string();
    let mut response = if method == Method::HEAD {
        Response::new(Body::empty())
    } else {
        let permit = state
            .stream_limit
            .clone()
            .acquire_owned()
            .await
            .map_err(ApiError::internal_with)?;
        let ip_limit = state
            .per_ip_stream_limits
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entry(peer.ip())
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STREAMS_PER_IP)))
            .clone();
        let ip_permit = ip_limit
            .acquire_owned()
            .await
            .map_err(ApiError::internal_with)?;
        let mut file = open_no_follow(&prepared.path)
            .await
            .map_err(|_| ApiError::not_found())?;
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(ApiError::internal_with)?;
        let stream = futures_util::stream::unfold(
            (
                ReaderStream::new(file.take(content_length)),
                permit,
                ip_permit,
            ),
            |(mut stream, permit, ip_permit)| async move {
                stream
                    .next()
                    .await
                    .map(|item| (item, (stream, permit, ip_permit)))
            },
        );
        let body = Body::from_stream(stream);
        Response::new(body)
    };
    *response.status_mut() = status;
    let response_headers = response.headers_mut();
    response_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&prepared.entry.media_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    response_headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string()).map_err(ApiError::internal_with)?,
    );
    response_headers.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(ApiError::internal_with)?,
    );
    response_headers.insert(
        header::LAST_MODIFIED,
        HeaderValue::from_str(&httpdate::fmt_http_date(modified))
            .map_err(ApiError::internal_with)?,
    );
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("{disposition}; filename*=UTF-8''{encoded_name}"))
            .map_err(ApiError::internal_with)?,
    );
    if status == StatusCode::PARTIAL_CONTENT {
        response_headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{total}"))
                .map_err(ApiError::internal_with)?,
        );
    }
    tracing::info!(
        event = if query.download {
            "web.file.downloaded"
        } else {
            "web.file.previewed"
        },
        source_address_family = address_family(peer.ip()),
        path_depth = relative_path_depth(&query.path),
        bytes = content_length
    );
    Ok(response)
}

async fn open_no_follow(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        options.open(path).map(tokio::fs::File::from_std)
    }
    #[cfg(not(unix))]
    {
        tokio::fs::File::open(path).await
    }
}

fn address_family(address: IpAddr) -> &'static str {
    if address.is_ipv4() {
        "ipv4"
    } else {
        "ipv6"
    }
}

fn relative_path_depth(path: &str) -> usize {
    path.split('/')
        .filter(|component| !component.is_empty())
        .count()
}

fn parse_range(
    value: Option<&HeaderValue>,
    total: u64,
) -> Result<Option<RangeInclusive<u64>>, ApiError> {
    let Some(value) = value.and_then(|value| value.to_str().ok()) else {
        return Ok(None);
    };
    let Some(value) = value.strip_prefix("bytes=") else {
        return Err(ApiError::range(total));
    };
    if value.contains(',') || total == 0 {
        return Err(ApiError::range(total));
    }
    let (start, end) = value
        .split_once('-')
        .ok_or_else(|| ApiError::range(total))?;
    let (start, end) = if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| ApiError::range(total))?;
        if suffix == 0 {
            return Err(ApiError::range(total));
        }
        (total.saturating_sub(suffix), total - 1)
    } else {
        let start = start.parse::<u64>().map_err(|_| ApiError::range(total))?;
        let end = if end.is_empty() {
            total - 1
        } else {
            end.parse::<u64>()
                .map_err(|_| ApiError::range(total))?
                .min(total - 1)
        };
        (start, end)
    };
    if start >= total || start > end {
        return Err(ApiError::range(total));
    }
    Ok(Some(start..=end))
}

fn if_range_matches(headers: &HeaderMap, etag: &str, modified: SystemTime) -> bool {
    let Some(value) = headers
        .get(header::IF_RANGE)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    if value.starts_with('"') {
        value == etag
    } else {
        httpdate::parse_http_date(value)
            .ok()
            .is_some_and(|date| modified <= date + Duration::from_secs(1))
    }
}

fn authorized_share(
    state: &GatewayState,
    headers: &HeaderMap,
    source_ip: IpAddr,
    slug: &str,
) -> Result<SharedDirectory, ApiError> {
    let share = state
        .files
        .web_share_by_slug(slug)
        .ok_or_else(ApiError::not_found)?;
    if share.web.mode == WebAccessMode::Public {
        return Ok(share);
    }
    if state.sessions.authorized(
        session_cookie(headers).as_deref(),
        source_ip,
        &share.id,
        share.web.credential_revision,
        state.idle_lifetime(),
    ) {
        Ok(share)
    } else {
        Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "this shared directory must be unlocked",
        ))
    }
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|cookie| {
            cookie
                .strip_prefix(&format!("{SESSION_COOKIE}="))
                .map(str::to_string)
        })
        .filter(|token| token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn auth_rate_limited(state: &GatewayState, ip: IpAddr, slug: &str) -> bool {
    let now = Instant::now();
    let mut failures = state
        .failed_auth
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let values = failures.entry((ip, slug.to_string())).or_default();
    while values
        .front()
        .is_some_and(|attempt| now.duration_since(*attempt) >= Duration::from_secs(60))
    {
        values.pop_front();
    }
    values.len() >= MAX_FAILED_ATTEMPTS_PER_MINUTE
}

fn record_auth_failure(state: &GatewayState, ip: IpAddr, slug: &str) {
    state
        .failed_auth
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .entry((ip, slug.to_string()))
        .or_default()
        .push_back(Instant::now());
}

fn clear_auth_failures(state: &GatewayState, ip: IpAddr, slug: &str) {
    state
        .failed_auth
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&(ip, slug.to_string()));
}

async fn static_asset(request: Request<Body>) -> Response {
    crate::assets::asset(request.uri().path())
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; img-src 'self' data:; media-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
    error_id: Option<String>,
    content_range: Option<String>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code: match status {
                StatusCode::BAD_REQUEST => "web_gateway.invalid_request",
                StatusCode::UNAUTHORIZED => "web_gateway.unauthenticated",
                StatusCode::FORBIDDEN => "web_gateway.permission_denied",
                StatusCode::NOT_FOUND => "web_gateway.not_found",
                StatusCode::CONFLICT => "web_gateway.conflict",
                StatusCode::GONE => "web_gateway.expired",
                StatusCode::TOO_MANY_REQUESTS => "web_gateway.rate_limited",
                _ => "web_gateway.internal",
            }
            .into(),
            message: message.into(),
            error_id: None,
            content_range: None,
        }
    }

    fn bad_request(error: arcrelay_files::FileError) -> Self {
        let status = match &error {
            arcrelay_files::FileError::Invalid(_) => StatusCode::BAD_REQUEST,
            arcrelay_files::FileError::NotFound(_) => StatusCode::NOT_FOUND,
            arcrelay_files::FileError::DirectorySnapshotExpired(_) => StatusCode::GONE,
            arcrelay_files::FileError::Conflict(_) => StatusCode::CONFLICT,
            arcrelay_files::FileError::PermissionDenied(_) => StatusCode::FORBIDDEN,
            arcrelay_files::FileError::DirectoryQueryTooBroad(_) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            arcrelay_files::FileError::FileTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            arcrelay_files::FileError::InsufficientStorage(_) => StatusCode::INSUFFICIENT_STORAGE,
            arcrelay_files::FileError::Unavailable(_)
            | arcrelay_files::FileError::Io { .. }
            | arcrelay_files::FileError::Serialization(_)
            | arcrelay_files::FileError::PasswordHash(_)
            | arcrelay_files::FileError::Task(_)
            | arcrelay_files::FileError::Image(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let code = error.code();
        let internal = status == StatusCode::INTERNAL_SERVER_ERROR;
        let error_id = internal.then(|| format!("{:032x}", rand::random::<u128>()));
        if let Some(error_id) = error_id.as_deref() {
            tracing::error!(
                event = "web.request.failed",
                error_id,
                error_code = code,
                error = %error,
                "web request failed internally"
            );
        }
        Self {
            status,
            code: code.into(),
            message: if internal {
                "web service is temporarily unavailable".into()
            } else {
                error.to_string()
            },
            error_id,
            content_range: None,
        }
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "share or file not found")
    }

    fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "this operation is not permitted for the share",
        )
    }

    fn internal_with(error: impl std::fmt::Display) -> Self {
        let error_id = format!("{:032x}", rand::random::<u128>());
        tracing::error!(
            event = "web.request.failed",
            error_id,
            error_code = "web_gateway.internal",
            error = %error,
            "web request failed internally"
        );
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "web_gateway.internal".into(),
            message: "web service is temporarily unavailable".into(),
            error_id: Some(error_id),
            content_range: None,
        }
    }

    fn range(total: u64) -> Self {
        Self {
            status: StatusCode::RANGE_NOT_SATISFIABLE,
            code: "web_gateway.invalid_range".into(),
            message: "requested file range is invalid".into(),
            error_id: None,
            content_range: Some(format!("bytes */{total}")),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(serde_json::json!({
                "error": {
                    "code": self.code,
                    "message": self.message,
                    "errorId": self.error_id,
                }
            })),
        )
            .into_response();
        if let Some(value) = self
            .content_range
            .and_then(|value| HeaderValue::from_str(&value).ok())
        {
            response.headers_mut().insert(header::CONTENT_RANGE, value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcrelay_files::{WebAccessMode, WebSharePolicyUpdate};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[test]
    fn parses_media_ranges() {
        assert_eq!(
            parse_range(Some(&HeaderValue::from_static("bytes=10-19")), 100).unwrap(),
            Some(10..=19)
        );
        assert_eq!(
            parse_range(Some(&HeaderValue::from_static("bytes=-10")), 100).unwrap(),
            Some(90..=99)
        );
        assert!(parse_range(Some(&HeaderValue::from_static("bytes=100-")), 100).is_err());
        assert!(parse_range(Some(&HeaderValue::from_static("bytes=0-1,4-5")), 100).is_err());
    }

    #[test]
    fn password_failures_are_limited_before_an_expensive_hash() {
        let config = tempfile::tempdir().unwrap();
        let files = FileShareService::load(config.path()).unwrap();
        let state = GatewayState::new(
            files,
            Arc::new(SessionStore::default()),
            WebGatewaySettings::default(),
            Arc::<str>::from("test"),
        );
        let ip = "192.168.1.20".parse().unwrap();
        for _ in 0..MAX_FAILED_ATTEMPTS_PER_MINUTE {
            record_auth_failure(&state, ip, "share-id");
        }
        assert!(auth_rate_limited(&state, ip, "share-id"));
    }

    fn request(method: Method, uri: &str, host: &str, body: Body) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, host)
            .body(body)
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 41320))));
        request
    }

    fn test_app(mode: WebAccessMode) -> (Router, tempfile::TempDir, tempfile::TempDir, String) {
        let config = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        std::fs::write(shared.path().join("movie.mp4"), b"0123456789").unwrap();
        let files = FileShareService::load(config.path()).unwrap();
        let share = files.add_share(shared.path()).unwrap();
        files
            .set_web_policy(
                &share.id,
                WebSharePolicyUpdate {
                    mode,
                    listed: true,
                    allow_preview: true,
                    allow_download: true,
                },
                (mode == WebAccessMode::Password).then_some("correct horse battery staple"),
            )
            .unwrap();
        let slug = files.local_shares()[0].web.slug.clone();
        let state = GatewayState::new(
            files,
            Arc::new(SessionStore::default()),
            WebGatewaySettings {
                enabled: true,
                site_name: "Test Host".into(),
                allowed_hostnames: vec!["test.local".into()],
                ..WebGatewaySettings::default()
            },
            Arc::<str>::from("test"),
        );
        (router(state), config, shared, slug)
    }

    #[tokio::test]
    async fn rejects_untrusted_hosts_and_double_encoded_traversal() {
        let (app, _config, _shared, slug) = test_app(WebAccessMode::Public);
        let response = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/site",
                "evil.example",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);

        let response = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/api/v1/shares/{slug}/entries?path=%252e%252e%2Fsecret"),
                "localhost:8767",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            HeaderValue::from_static("nosniff")
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "files.invalid_argument");
        assert!(error["error"]["message"].is_string());

        let response = app
            .oneshot(request(Method::GET, "/", "localhost:8767", Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body
            .windows(b"web-files-app".len())
            .any(|window| window == b"web-files-app"));
    }

    #[tokio::test]
    async fn password_unlock_sets_http_only_cookie_and_authorizes_share() {
        let (app, _config, _shared, slug) = test_app(WebAccessMode::Password);
        let mut unlock_request = request(
            Method::POST,
            &format!("/api/v1/shares/{slug}/unlock"),
            "localhost:8767",
            Body::from(r#"{"password":"correct horse battery staple"}"#),
        );
        unlock_request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let response = app.clone().oneshot(unlock_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("HttpOnly; SameSite=Strict"));

        let mut authorized = request(
            Method::GET,
            &format!("/api/v1/shares/{slug}/entries?path="),
            "localhost:8767",
            Body::empty(),
        );
        authorized
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        let response = app.oneshot(authorized).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn streams_valid_ranges_and_rejects_invalid_ranges() {
        let (app, _config, _shared, slug) = test_app(WebAccessMode::Public);
        let mut ranged = request(
            Method::GET,
            &format!("/api/v1/shares/{slug}/content?path=movie.mp4"),
            "localhost:8767",
            Body::empty(),
        );
        ranged
            .headers_mut()
            .insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
        let response = app.clone().oneshot(ranged).await.unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 2-5/10");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "2345"
        );

        let mut invalid = request(
            Method::GET,
            &format!("/api/v1/shares/{slug}/content?path=movie.mp4"),
            "localhost:8767",
            Body::empty(),
        );
        invalid
            .headers_mut()
            .insert(header::RANGE, HeaderValue::from_static("bytes=20-30"));
        let response = app.oneshot(invalid).await.unwrap();
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes */10");
    }

    #[tokio::test]
    async fn internal_errors_hide_details_and_return_a_correlation_id() {
        let source = serde_json::from_str::<serde_json::Value>("private-data").unwrap_err();
        let response =
            ApiError::bad_request(arcrelay_files::FileError::Serialization(source)).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["error"]["message"],
            "web service is temporarily unavailable"
        );
        assert!(body["error"]["errorId"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(!body.to_string().contains("private-data"));
    }

    #[test]
    fn resource_exhaustion_uses_actionable_http_statuses() {
        assert_eq!(
            ApiError::bad_request(arcrelay_files::FileError::DirectoryQueryTooBroad(
                "too many entries".into()
            ))
            .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            ApiError::bad_request(arcrelay_files::FileError::FileTooLarge("too large".into()))
                .status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            ApiError::bad_request(arcrelay_files::FileError::InsufficientStorage(
                "disk full".into()
            ))
            .status,
            StatusCode::INSUFFICIENT_STORAGE
        );
    }
}
