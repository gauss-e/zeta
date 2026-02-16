use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, HeaderName, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use futures_util::TryStreamExt;
use reqwest::Client;
use tracing::{error, info};
use url::Url;

mod crypto;
use crypto::UrlCrypto;

const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Clone)]
struct Config {
    listen_addr: SocketAddr,
    aes_password: String,
    url_param_name: String,
    request_timeout_secs: u64,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let listen_addr =
            std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let aes_password = std::env::var("AES_PASSWORD").map_err(|_| {
            anyhow::anyhow!(
                "missing env: AES_PASSWORD. Fix: set AES_PASSWORD in ./config or in your RustRover Run Configuration."
            )
        })?;
        let url_param_name = std::env::var("URL_PARAM_NAME").unwrap_or_else(|_| "oeid".to_string());
        let request_timeout_secs = std::env::var("REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30);

        let listen_addr = SocketAddr::from_str(&listen_addr)
            .map_err(|e| anyhow::anyhow!("invalid LISTEN_ADDR: {e}"))?;

        Ok(Self {
            listen_addr,
            aes_password,
            url_param_name,
            request_timeout_secs,
        })
    }
}

#[derive(Clone)]
struct AppState {
    client: Client,
    config: Arc<Config>,
    url_crypto: Arc<UrlCrypto>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::from_filename("config");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,passthrough_proxy=debug".into()),
        )
        .init();

    let config = Arc::new(Config::from_env()?);

    let client = Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(64)
        .http2_adaptive_window(true)
        .timeout(Duration::from_secs(config.request_timeout_secs))
        .build()?;

    let url_crypto = Arc::new(UrlCrypto::from_password(&config.aes_password).unwrap());
    let state = AppState {
        client,
        config,
        url_crypto,
    };

    let app = Router::new()
        .route("/data", any(proxy))
        .with_state(state.clone());

    info!("listening on {}", state.config.listen_addr);
    let listener = tokio::net::TcpListener::bind(state.config.listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn proxy(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    req: Request<Body>,
) -> Result<Response, ProxyError> {
    let encrypted = params
        .get(&state.config.url_param_name)
        .or_else(|| params.get("oeid"))
        .ok_or_else(|| {
            ProxyError::bad_request(format!(
                "missing query param: {}",
                state.config.url_param_name
            ))
        })?;

    let upstream_url = state
        .url_crypto
        .decrypt_param(encrypted)
        .map(|s| format!("https://x.com/?{}", s.trim_start_matches('&')))
        .and_then(|u| Ok(Url::parse(&u)?))
        .and_then(|url| {
            url.query_pairs()
                .find(|(k, _)| k == "url")
                .map(|(_, v)| v.into_owned())
                .ok_or_else(|| "missing url".into())
        })
        .map_err(|e| ProxyError::bad_request(e.to_string()))?;

    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_stream = req.into_body().into_data_stream();
    let reqwest_body = reqwest::Body::wrap_stream(body_stream);

    let mut builder = state.client.request(method, upstream_url);

    let mut forwarded_headers = HeaderMap::new();
    copy_request_headers(&headers, &mut forwarded_headers);
    builder = builder.headers(forwarded_headers);

    let upstream_resp = builder
        .body(reqwest_body)
        .send()
        .await
        .map_err(ProxyError::upstream)?;

    let status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();

    let stream = upstream_resp
        .bytes_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));

    let mut downstream = Response::builder()
        .status(status)
        .body(Body::from_stream(stream))
        .map_err(|e| ProxyError::internal(anyhow::anyhow!(e)))?;

    copy_response_headers(&upstream_headers, downstream.headers_mut());

    Ok(downstream)
}

fn copy_request_headers(src: &HeaderMap, dst: &mut HeaderMap) {
    for (name, value) in src {
        if !is_hop_by_hop(name)
            && name != http::header::HOST
            && name != http::header::CONTENT_LENGTH
        {
            dst.append(name.clone(), value.clone());
        }
    }
}

fn copy_response_headers(src: &HeaderMap, dst: &mut HeaderMap) {
    for (name, value) in src {
        if !is_hop_by_hop(name) {
            dst.append(name.clone(), value.clone());
        }
    }
}

fn is_hop_by_hop(header_name: &HeaderName) -> bool {
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|h| header_name.as_str().eq_ignore_ascii_case(h))
}

#[derive(Debug)]
struct ProxyError {
    status: StatusCode,
    message: String,
}

impl ProxyError {
    fn bad_request(message: String) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn upstream(err: reqwest::Error) -> Self {
        let status = if err.is_timeout() {
            StatusCode::GATEWAY_TIMEOUT
        } else {
            StatusCode::BAD_GATEWAY
        };
        Self {
            status,
            message: format!("upstream request failed: {err}"),
        }
    }

    fn internal(err: anyhow::Error) -> Self {
        error!("internal error: {err}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
        }
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}
