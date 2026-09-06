use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets/"]
struct WebAssets;

pub(crate) fn asset(path: &str) -> Response {
    let requested = path.trim_start_matches('/');
    let key = if requested.is_empty() || requested == "files" || requested.starts_with("s/") {
        "web-files.html"
    } else {
        requested
    };
    let Some(file) = WebAssets::get(key) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let media_type = mime_guess::from_path(key)
        .first_raw()
        .unwrap_or("application/octet-stream");
    let mut response = file.data.into_owned().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(media_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if key == "web-files.html" {
            "no-store"
        } else {
            "public, max-age=31536000, immutable"
        }),
    );
    response
}
