// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]
#![warn(clippy::all, rust_2018_idioms, unused_lifetimes)]

mod auth;
mod redirect;
mod templates;

use crate::auth::{Claims, ClaimsError};
use crate::templates::{HtmlTemplate, RootGetTemplate, UuidGetTemplate};

use std::collections::HashMap;
use std::fs::read;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use auth::WorkloadSession;
use axum::extract::Multipart;
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Router, Server};

use anyhow::{bail, Context as _};
use clap::Parser;
use once_cell::sync::Lazy;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client as client;
use openidconnect::url::Url;
use openidconnect::{AccessToken, AuthType, ClientId, ClientSecret, IssuerUrl, RedirectUrl};
use serde::Deserialize;
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, timeout};
use tower_http::trace::TraceLayer;
use tracing::error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

const ENARX_REPO: &str = "enarx/enarx";
// TODO: raise this when this is fixed: https://github.com/profianinc/benefice/issues/75
const READ_TIMEOUT: Duration = Duration::from_millis(500);
const TOML_MAX: usize = 256 * 1024; // 256 KiB

static CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

    reqwest::ClientBuilder::new()
        .user_agent(USER_AGENT)
        .build()
        .unwrap()
});

#[allow(dead_code)]
struct State {
    exec: Child,
    wasm: NamedTempFile,
    toml: NamedTempFile,
    user: String,
    token: AccessToken,
}

static OUT: Lazy<RwLock<HashMap<Uuid, Arc<Mutex<State>>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Demo workload executor.
///
/// Any command-line options listed here may be specified by one or
/// more configuration files, which can be used by passing the
/// name of the file on the command-line with the syntax `@config.toml`.
/// The configuration file must contain valid TOML table mapping argument
/// names to their values.
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Address to bind to.
    #[clap(long, default_value_t = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000))]
    addr: SocketAddr,

    /// Externally accessible root URL.
    /// For example: https://benefice.example.com
    #[clap(long)]
    url: Url,

    /// Maximum jobs.
    #[clap(long, default_value_t = num_cpus::get())]
    jobs: usize,

    /// Default file size limit (in MiB).
    #[clap(long, default_value_t = 10)]
    size_limit_default: usize,

    /// Starred file size limit (in MiB).
    #[clap(long, default_value_t = 50)]
    size_limit_starred: usize,

    /// Default job timeout (in minutes).
    #[clap(long, default_value_t = 5)]
    timeout_default: u64,

    /// Starred job timeout (in minutes).
    #[clap(long, default_value_t = 30)]
    timeout_starred: u64,

    /// Command to execute, normally path to `enarx` binary.
    /// This command will be executed as: `<cmd> run --wasmcfgfile <path-to-config> <path-to-wasm>`
    #[clap(long, default_value = "enarx")]
    command: String,

    /// OpenID Connect issuer URL.
    #[clap(long, default_value = "https://auth.profian.com/")]
    oidc_issuer: Url,

    /// OpenID Connect client ID.
    #[clap(long)]
    oidc_client: String,

    /// Path to a file containing OpenID Connect secret.
    #[clap(long)]
    oidc_secret: Option<String>,
}

impl Args {
    fn limits(&self) -> Limits {
        Limits {
            size_limit_default: self.size_limit_default,
            size_limit_starred: self.size_limit_starred,
            timeout_default: self.timeout_default,
            timeout_starred: self.timeout_starred,
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct Limits {
    size_limit_default: usize,
    size_limit_starred: usize,
    timeout_default: u64,
    timeout_starred: u64,
}

impl Limits {
    // TODO: use auth0 for this instead of github directly: https://github.com/profianinc/benefice/issues/71
    pub async fn decide(&self, claims: Option<&Claims>) -> Context {
        #[derive(Debug, Deserialize)]
        struct Repo {
            pub full_name: String,
        }

        let user = claims
            .and_then(|claims| claims.github())
            .map(|s| s.to_owned());

        let star = match user.as_ref() {
            None => false,
            Some(id) => {
                match CLIENT
                    .get(&format!("https://api.github.com/user/{id}/starred"))
                    .send()
                    .await
                {
                    Err(..) => false,
                    Ok(response) => match response.json::<Vec<Repo>>().await {
                        Ok(repos) => repos.iter().any(|repo| repo.full_name == ENARX_REPO),
                        Err(..) => false,
                    },
                }
            }
        };

        let size_limit = match star {
            false => self.size_limit_default,
            true => self.size_limit_starred,
        };

        let timeout = match star {
            false => self.timeout_default,
            true => self.timeout_starred,
        };

        Context {
            size_limit,
            timeout,
            star,
            user,
        }
    }
}

pub struct Context {
    size_limit: usize,
    timeout: u64,
    star: bool,
    user: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args()
        .try_fold(Vec::new(), |mut args, arg| {
            if let Some(path) = arg.strip_prefix('@') {
                let conf = read(path).context(format!("failed to read config file at `{path}`"))?;
                match toml::from_slice(&conf)
                    .context(format!("failed to parse config file at `{path}` as TOML"))?
                {
                    toml::Value::Table(kv) => kv.into_iter().try_for_each(|(k, v)| {
                        match v {
                            toml::Value::String(v) => args.push(format!("--{k}={v}")),
                            toml::Value::Integer(v) => args.push(format!("--{k}={v}")),
                            toml::Value::Float(v) => args.push(format!("--{k}={v}")),
                            toml::Value::Boolean(v) => {
                                if v {
                                    args.push(format!("--{k}"))
                                }
                            }
                            _ => bail!(
                                "unsupported value type for field `{k}` in config file at `{path}`"
                            ),
                        }
                        Ok(())
                    })?,
                    _ => bail!("invalid config file format in file at `{path}`"),
                }
            } else {
                args.push(arg);
            }
            Ok(args)
        })
        .map(Args::parse_from)
        .context("Failed to parse arguments")?;

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "example_tracing_aka_logging=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let limits = args.limits();
    let oidc_secret = args
        .oidc_secret
        .map(|ref path| {
            read(path).with_context(|| format!("Failed to read OpenID Connect secret at `{path}`"))
        })
        .transpose()?
        .map(String::from_utf8)
        .transpose()
        .context("OpenID Connect secret is not valid UTF-8")?
        .map(|secret| secret.trim().to_string());
    let issuer_url = IssuerUrl::from_url(args.oidc_issuer);
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, client).await?;
    let openid_client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(args.oidc_client),
        oidc_secret.map(ClientSecret::new),
    )
    .set_redirect_uri(RedirectUrl::from_url(
        args.url
            .join("/authorized")
            .with_context(|| "failed to append /authorized path to url")?,
    ))
    .set_auth_type(AuthType::RequestBody);

    let app = Router::new()
        .route("/login", get(auth::login))
        .route("/logout", get(auth::logout))
        .route("/authorized", get(auth::authorized))
        .route("/:uuid/", get(uuid_get))
        .route("/:uuid/out", post(uuid_out_post))
        .route("/:uuid/err", post(uuid_err_post))
        .route("/:uuid/kill", get(uuid_kill_get))
        .route(
            "/",
            get(move |claims, session| root_get(claims, session, limits))
                .post(move |claims, mp| root_post(claims, mp, args.command, limits, args.jobs)),
        )
        .layer(Extension(openid_client))
        .layer(TraceLayer::new_for_http());

    Server::bind(&args.addr)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn root_get(
    claims: Option<Claims>,
    session: Option<WorkloadSession>,
    limits: Limits,
) -> impl IntoResponse {
    if let Some(session) = session {
        return redirect::workload(&session.workload_uuid).into_response();
    }

    HtmlTemplate(RootGetTemplate {
        toml: enarx_config::CONFIG_TEMPLATE,
        ctx: limits.decide(claims.as_ref()).await,
    })
    .into_response()
}

// TODO: create tests for endpoints: #38
async fn root_post(
    claims: Result<Claims, ClaimsError>,
    mut multipart: Multipart,
    command: String,
    limits: Limits,
    jobs: usize,
) -> impl IntoResponse {
    let claims = claims.map_err(|e| e.redirect_response().into_response())?;
    let ctx = limits.decide(Some(&claims)).await;

    // Detect too many jobs early.
    {
        let mut jobs_to_kill = vec![];

        let lock = OUT.read().await;

        if lock.len() >= jobs {
            return Err(redirect::too_many_workloads().into_response());
        }

        for (key, state) in &*lock {
            let lock = state.lock().await;

            if lock.user == *ctx.user.as_ref().unwrap() {
                jobs_to_kill.push(*key);
            }
        }

        {
            let mut lock = OUT.write().await;

            if !jobs_to_kill.is_empty() {
                for uuid in jobs_to_kill {
                    lock.remove(&uuid);
                }
            }
        }
    }

    let mut wasm = None;
    let mut toml = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?
    {
        match field.name() {
            Some("wasm") => {
                if Some("application/wasm") != field.content_type() {
                    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
                }

                if wasm.is_some() {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }

                let mut len = 0;
                let mut out = tempfile::NamedTempFile::new()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| StatusCode::BAD_REQUEST.into_response())?
                {
                    len += chunk.len();
                    if len > ctx.size_limit * 1024 * 1024 {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
                    }

                    out.write_all(&chunk)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
                }

                wasm = Some(out);
            }

            Some("toml") => {
                if field.content_type().is_some() {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }

                if toml.is_some() {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }

                let mut len = 0;
                let mut out = tempfile::NamedTempFile::new()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| StatusCode::BAD_REQUEST.into_response())?
                {
                    len += chunk.len();
                    if len > TOML_MAX {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
                    }

                    out.write_all(&chunk)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
                }

                toml = Some(out);
            }

            _ => continue,
        }
    }

    let wasm = wasm.ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
    let toml = toml.ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
    let uuid = Uuid::new_v4();
    let exec = Command::new(command)
        .arg("run")
        .arg("--wasmcfgfile")
        .arg(toml.path())
        .arg(wasm.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            error!("failed to spawn process: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let mut lock = OUT.write().await;

    // Final confirmation that we will allow this job.
    if lock.len() >= jobs {
        return Err(StatusCode::TOO_MANY_REQUESTS.into_response());
    }

    lock.insert(
        uuid,
        Arc::new(Mutex::new(State {
            exec,
            wasm,
            toml,
            user: ctx.user.unwrap(),
            token: claims.token().clone(),
        })),
    );

    tokio::spawn(async move {
        // Convert from minutes to seconds.
        sleep(Duration::from_secs(ctx.timeout * 60)).await;
        OUT.write().await.remove(&uuid);
    });

    Ok((StatusCode::SEE_OTHER, [("Location", format!("/{}", uuid))]))
}

async fn uuid_get(
    Path(uuid): Path<String>,
    claims: Result<Claims, ClaimsError>,
) -> impl IntoResponse {
    let uuid: Uuid = uuid.parse().map_err(|_| redirect::workload_not_found())?;
    let lock = OUT.read().await;
    let exec = lock.get(&uuid).ok_or_else(redirect::workload_not_found)?;
    let claims = claims.map_err(|e| e.redirect_response())?;
    let user = claims.subject().to_string();

    if exec.lock().await.user != user {
        return Err(redirect::workload_not_found());
    }

    Ok(HtmlTemplate(UuidGetTemplate {}))
}

async fn uuid_out_post(
    Path(uuid): Path<String>,
    session: WorkloadSession,
) -> Result<impl IntoResponse, StatusCode> {
    let mut buf = [0; 4096];

    let uuid: Uuid = uuid.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let exec = OUT
        .read()
        .await
        .get(&uuid)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    if exec.lock().await.user != session.user {
        return Err(StatusCode::NOT_FOUND);
    }

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

async fn uuid_err_post(
    Path(uuid): Path<String>,
    session: WorkloadSession,
) -> Result<impl IntoResponse, StatusCode> {
    let mut buf = [0; 4096];

    let uuid: Uuid = uuid.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let exec = OUT
        .read()
        .await
        .get(&uuid)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    if exec.lock().await.user != session.user {
        return Err(StatusCode::NOT_FOUND);
    }

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

async fn uuid_kill_get(
    Path(uuid): Path<String>,
    session: Option<WorkloadSession>,
) -> Result<Redirect, Redirect> {
    let session = session.ok_or_else(redirect::home)?;
    let uuid: Uuid = uuid.parse().map_err(|_| redirect::home())?;
    let exec = OUT
        .read()
        .await
        .get(&uuid)
        .ok_or_else(redirect::home)?
        .clone();

    if exec.lock().await.user != session.user {
        return Err(redirect::home());
    }

    OUT.write()
        .await
        .remove(&uuid)
        .map(|_| redirect::workload_killed())
        .ok_or_else(redirect::workload_not_found)
}
