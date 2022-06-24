use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use benefice_auth::providers::github;
use benefice_auth::{AuthRedirectRoot, Session};

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{extract::Multipart, response::Html};
use axum::{Extension, Router, Server};

use once_cell::sync::Lazy;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, timeout};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const VIEW_TIMEOUT: Duration = Duration::from_secs(10);
const WASM_MAX: usize = 25 * 1024 * 1024; // 25 MiB
const TOML_MAX: usize = 256 * 1024; // 256 KiB

#[allow(dead_code)]
struct State {
    exec: Child,
    wasm: NamedTempFile,
    toml: NamedTempFile,
}

static OUT: Lazy<RwLock<HashMap<Uuid, Arc<Mutex<State>>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "example_tracing_aka_logging=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let key = RsaPrivateKey::from_pkcs8_der(&std::fs::read("key.der").expect("read key.der file"))
        .expect("parse key.der");

    let host = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000);

    let app = Router::new()
        .route(github::AUTHORIZED_URI, get(github::routes::authorized))
        .route(github::LOGIN_URI, get(github::routes::login))
        .route(github::LOGOUT_URI, get(github::routes::logout))
        .route("/:uuid/", get(uuid_get))
        .route("/:uuid/out", post(uuid_out_post))
        .route("/:uuid/err", post(uuid_err_post))
        .route("/", get(root_get).post(root_post))
        .layer(Extension(key))
        .layer(Extension(AuthRedirectRoot(host.to_string())))
        .layer(Extension(github::OAuthClient::new(
            &host.to_string(),
            std::env::var("CLIENT_ID").expect("github oauth CLIENT_ID"),
            std::env::var("CLIENT_SECRET").expect("github oauth CLIENT_SECRET"),
        )))
        .layer(TraceLayer::new_for_http());

    Server::bind(&host)
        .serve(app.into_make_service())
        .await
        .unwrap()
}

async fn root_get() -> Html<&'static str> {
    Html(include_str!("root_get.html"))
}

async fn root_post(
    mut multipart: Multipart,
    session: Option<Session>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut wasm = None;
    let mut toml = None;

    if session.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        match field.name() {
            Some("wasm") => {
                if Some("application/wasm") != field.content_type() {
                    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
                }

                if wasm.is_some() {
                    return Err(StatusCode::BAD_REQUEST);
                }

                let mut len = 0;
                let mut out = tempfile::NamedTempFile::new()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                while let Some(chunk) = field.chunk().await.map_err(|_| StatusCode::BAD_REQUEST)? {
                    len += chunk.len();
                    if len > WASM_MAX {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }

                    out.write_all(&chunk)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                }

                wasm = Some(out);
            }

            Some("toml") => {
                if field.content_type().is_some() {
                    return Err(StatusCode::BAD_REQUEST);
                }

                if toml.is_some() {
                    return Err(StatusCode::BAD_REQUEST);
                }

                let mut len = 0;
                let mut out = tempfile::NamedTempFile::new()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                while let Some(chunk) = field.chunk().await.map_err(|_| StatusCode::BAD_REQUEST)? {
                    len += chunk.len();
                    if len > TOML_MAX {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }

                    out.write_all(&chunk)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                }

                toml = Some(out);
            }

            _ => continue,
        }
    }

    let wasm = wasm.ok_or(StatusCode::BAD_REQUEST)?;
    let toml = toml.ok_or(StatusCode::BAD_REQUEST)?;
    let uuid = Uuid::new_v4();
    let exec = Command::new("enarx")
        .arg("run")
        .arg("--wasmcfgfile")
        .arg(toml.path())
        .arg(wasm.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    OUT.write()
        .await
        .insert(uuid, Arc::new(Mutex::new(State { exec, wasm, toml })));

    tokio::spawn(async move {
        sleep(VIEW_TIMEOUT).await;
        OUT.write().await.remove(&uuid);
    });

    Ok((StatusCode::SEE_OTHER, [("Location", format!("/{}", uuid))]))
}

async fn uuid_get(Path(uuid): Path<String>) -> Result<impl IntoResponse, StatusCode> {
    let uuid: Uuid = uuid.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    OUT.read().await.get(&uuid).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Html(include_str!("uuid_get.html")))
}

async fn uuid_out_post(Path(uuid): Path<String>) -> Result<impl IntoResponse, StatusCode> {
    let mut buf = [0; 4096];

    let uuid: Uuid = uuid.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let exec = OUT
        .read()
        .await
        .get(&uuid)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    let future = async {
        exec.lock()
            .await
            .exec
            .stdout
            .as_mut()
            .unwrap()
            .read(&mut buf)
            .await
    };

    match timeout(READ_TIMEOUT, future).await {
        Ok(Err(..)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Ok(Ok(size)) => Ok(buf[..size].to_vec()),
        Err(..) => Ok(Vec::new()),
    }
}

async fn uuid_err_post(Path(uuid): Path<String>) -> Result<impl IntoResponse, StatusCode> {
    let mut buf = [0; 4096];

    let uuid: Uuid = uuid.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let exec = OUT
        .read()
        .await
        .get(&uuid)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    let future = async {
        exec.lock()
            .await
            .exec
            .stderr
            .as_mut()
            .unwrap()
            .read(&mut buf)
            .await
    };

    match timeout(READ_TIMEOUT, future).await {
        Ok(Err(..)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Ok(Ok(size)) => Ok(buf[..size].to_vec()),
        Err(..) => Ok(Vec::new()),
    }
}
