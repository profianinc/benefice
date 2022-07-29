// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]
#![warn(clippy::all, rust_2018_idioms, unused_lifetimes)]

mod auth;
mod job;
mod jobs;
mod redirect;
mod secret;
mod templates;

use self::auth::{Key, Oidc, User};
use self::job::{Job, Standard};
use self::jobs::Jobs;
use crate::templates::{HtmlTemplate, IdxTemplate, JobTemplate};

use std::fs::read;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::extract::Multipart;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::routing::post;
use axum::{Router, Server};

use anyhow::{bail, Context as _};
use clap::Parser;
use once_cell::sync::Lazy;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

// TODO: raise this when this is fixed: https://github.com/profianinc/benefice/issues/75
const READ_TIMEOUT: Duration = Duration::from_millis(500);
const TOML_MAX: usize = 256 * 1024; // 256 KiB

static JOBS: Lazy<RwLock<Jobs>> = Lazy::new(Default::default);

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
    url: auth::Url,

    /// Maximum jobs.
    #[clap(long, default_value_t = num_cpus::get())]
    jobs: usize,

    /// Default file size limit (in MiB).
    #[clap(long, default_value_t = 10)]
    size_limit_default: usize,

    /// Starred file size limit (in MiB).
    #[clap(long, default_value_t = 50)]
    size_limit_starred: usize,

    /// Default job timeout (in seconds).
    #[clap(long, default_value_t = 5 * 60)]
    timeout_default: u64,

    /// Starred job timeout (in seconds).
    #[clap(long, default_value_t = 15 * 60)]
    timeout_starred: u64,

    /// Command to execute, normally path to `enarx` binary.
    /// This command will be executed as: `<cmd> run --wasmcfgfile <path-to-config> <path-to-wasm>`
    #[clap(long, default_value = "enarx")]
    command: String,

    /// OpenID Connect issuer URL.
    #[clap(long, default_value = "https://auth.profian.com/")]
    oidc_issuer: auth::Url,

    /// OpenID Connect client ID.
    #[clap(long)]
    oidc_client: String,

    /// Path to a file containing OpenID Connect secret.
    #[clap(long)]
    oidc_secret: Option<secret::SecretFile<String>>,

    /// Key used to encrypt the session cookie.
    #[clap(long)]
    session_key: Option<secret::SecretFile<Key>>,

    /// Session cookie time to live (in minutes).
    #[clap(long, default_value_t = 24 * 60)]
    session_ttl: u64,
}

impl Args {
    fn split(self) -> (Limits, Create, Oidc, SocketAddr) {
        let limits = Limits {
            size_limit_default: self.size_limit_default,
            size_limit_starred: self.size_limit_starred,
            timeout_default: Duration::from_secs(self.timeout_default),
            timeout_starred: Duration::from_secs(self.timeout_starred),
        };

        let create = Create {
            command: self.command,
            jobs: self.jobs,
            limits,
        };

        let oidc = Oidc {
            server: self.url,
            issuer: self.oidc_issuer,
            client: self.oidc_client,
            secret: self.oidc_secret.map(|sf| sf.into()),
            session_ttl: Duration::from_secs(self.session_ttl * 60),
            session_key: self.session_key.map(|k| k.into()).unwrap_or_default(),
        };

        (limits, create, oidc, self.addr)
    }
}

#[derive(Clone, Debug)]
struct Create {
    command: String,
    limits: Limits,
    jobs: usize,
}

#[derive(Copy, Clone, Debug)]
struct Limits {
    size_limit_default: usize,
    size_limit_starred: usize,
    timeout_default: Duration,
    timeout_starred: Duration,
}

impl Limits {
    pub fn decide(&self, star: bool) -> (Duration, usize) {
        let size = match star {
            false => self.size_limit_default,
            true => self.size_limit_starred,
        };

        let ttl = match star {
            false => self.timeout_default,
            true => self.timeout_starred,
        };

        (ttl, size)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (limits, create, oidc, addr) = std::env::args()
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
        .context("Failed to parse arguments")?
        .split();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "example_tracing_aka_logging=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let root = post(move |user, mp| root_post(user, mp, create))
        .get(move |user| root_get(user, limits))
        .delete(root_delete);

    let app = Router::new()
        .route("/out", post(move |user| reader(user, Standard::Output)))
        .route("/err", post(move |user| reader(user, Standard::Error)))
        .route("/", root);

    let app = oidc.routes(app).await?;

    Server::bind(&addr)
        .serve(app.layer(TraceLayer::new_for_http()).into_make_service())
        .await?;

    Ok(())
}

async fn root_get(user: Option<User>, limits: Limits) -> impl IntoResponse {
    let (user, star) = match user {
        None => (false, false),
        Some(user) => {
            if JOBS.read().await.by_user(&user).is_some() {
                return HtmlTemplate(JobTemplate).into_response();
            }

            (true, user.is_starred("enarx/enarx").await)
        }
    };

    let (ttl, size) = limits.decide(star);

    let tmpl = IdxTemplate {
        toml: enarx_config::CONFIG_TEMPLATE,
        user,
        star,
        size,
        ttl: ttl.as_secs(),
    };

    HtmlTemplate(tmpl).into_response()
}

// TODO: create tests for endpoints: #38
async fn root_post(user: User, mut multipart: Multipart, create: Create) -> impl IntoResponse {
    if JOBS.read().await.by_user(&user).is_some() {
        return Err(Redirect::to("/").into_response());
    }

    if JOBS.read().await.i2j.len() >= create.jobs {
        return Err(redirect::too_many_workloads().into_response());
    }

    let (ttl, size) = create.limits.decide(user.is_starred("enarx/enarx").await);

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
                    if len > size * 1024 * 1024 {
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

    // Create the new job.
    let uuid = Uuid::new_v4();
    {
        let mut lock = JOBS.write().await;

        if JOBS.read().await.by_user(&user).is_some() {
            return Err(Redirect::to("/").into_response());
        }

        if JOBS.read().await.i2j.len() >= create.jobs {
            return Err(redirect::too_many_workloads().into_response());
        }

        let job = Job::new(create.command, wasm, toml).map_err(|e| {
            error!("failed to spawn process: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

        lock.i2j.insert(uuid, RwLock::new(job).into());
        lock.u2i.insert(user, uuid);
    }

    // Set the job timeout.
    tokio::spawn(async move {
        sleep(ttl).await;
        let mut lock = JOBS.write().await;

        if lock.i2j.remove(&uuid).is_some() {
            debug!("timeout for: {}", uuid);
        }

        if lock.u2i.get(&user) == Some(&uuid) {
            lock.u2i.remove(&user);
        }
    });

    info!("job started. job_id={uuid}, user_id={}", user);
    Ok((StatusCode::SEE_OTHER, [("Location", "/")]))
}

async fn root_delete(user: User) -> StatusCode {
    let mut lock = JOBS.write().await;

    if let Some(uuid) = lock.u2i.remove(&user) {
        if let Some(..) = lock.i2j.remove(&uuid) {
            debug!("killing: {}", uuid);
        }
    }

    StatusCode::OK
}

async fn reader(user: User, kind: Standard) -> Result<Vec<u8>, StatusCode> {
    if let Some(job) = JOBS.read().await.by_user(&user).cloned() {
        let mut buf = [0; 4096];
        let mut lock = job.write().await;
        let future = lock.read(kind, &mut buf);

        return match timeout(READ_TIMEOUT, future).await {
            Ok(Err(..)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            Ok(Ok(size)) => Ok(buf[..size].to_vec()),
            Err(..) => Ok(Vec::new()),
        };
    }

    Err(StatusCode::NOT_FOUND)
}
