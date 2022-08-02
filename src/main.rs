// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]
#![warn(clippy::all, rust_2018_idioms, unused_lifetimes)]

mod auth;
mod data;
mod jobs;
mod ports;
mod redirect;
mod reference;
mod secret;
mod templates;

use crate::data::Data;
use crate::reference::Ref;
use crate::templates::{HtmlTemplate, IdxTemplate, JobTemplate};

use std::fs::read;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::time::Duration;

use axum::extract::{Multipart, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Router, Server};

use anyhow::{bail, Context as _};
use clap::Parser;
use humansize::{file_size_opts as options, FileSize};
use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use reqwest::{Client, ClientBuilder};
use serde::Deserialize;
use tokio::fs::read_to_string;
use tokio::time::{sleep, timeout};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static HTTP: Lazy<Client> = Lazy::new(|| {
    const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
    ClientBuilder::new().user_agent(USER_AGENT).build().unwrap()
});

// TODO: raise this when this is fixed: https://github.com/profianinc/benefice/issues/75
const READ_TIMEOUT: Duration = Duration::from_millis(500);
const TOML_MAX: usize = 256 * 1024; // 256 KiB

lazy_static! {
    static ref EXAMPLES: Vec<&'static str> = include_str!("../examples.txt")
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
}

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

    /// The lowest listen port allowed in an Enarx.toml.
    #[clap(long, default_value_t = 0)]
    port_min: u16,

    /// The highest listen port allowed in an Enarx.toml.
    #[clap(long, default_value_t = 0)]
    port_max: u16,

    /// The maximum number of listen ports a workload is allowed to have (0 to disable).
    #[clap(long, default_value_t = 0)]
    listen_max: u16,

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
    oidc_secret: Option<secret::SecretFile>,
}

impl Args {
    fn split(self) -> (Limits, auth::Oidc, Other) {
        let limits = Limits {
            size_limit_default: self.size_limit_default,
            size_limit_starred: self.size_limit_starred,
            timeout_default: Duration::from_secs(self.timeout_default),
            timeout_starred: Duration::from_secs(self.timeout_starred),
        };

        let oidc = auth::Oidc {
            server: self.url,
            issuer: self.oidc_issuer,
            client: self.oidc_client,
            secret: self.oidc_secret.map(|sf| sf.into()),
            ttl: Duration::from_secs(24 * 60 * 60),
        };

        let other = Other {
            addr: self.addr,
            jobs: self.jobs,
            port_range: match (self.port_min, self.port_max) {
                (0, 0) => None,
                (min, 0) => Some(min..u16::MAX),
                (min, max) => Some(min..max),
            },
            listen_max: if self.listen_max == 0 {
                None
            } else {
                Some(self.listen_max)
            },
            cmd: self.command,
        };

        (limits, oidc, other)
    }
}

#[derive(Copy, Clone, Debug)]
struct Limits {
    /// Size in megabytes
    size_limit_default: usize,
    /// Size in megabytes
    size_limit_starred: usize,
    timeout_default: Duration,
    timeout_starred: Duration,
}

impl Limits {
    pub fn time_to_live(&self, star: bool) -> Duration {
        if star {
            self.timeout_default
        } else {
            self.timeout_starred
        }
    }

    /// Get the maximum allowed wasm size in bytes.
    pub fn size(&self, star: bool) -> usize {
        let size_megabytes = if star {
            self.size_limit_default
        } else {
            self.size_limit_starred
        };
        size_megabytes * 1024 * 1024
    }

    pub fn size_human(&self, star: bool) -> String {
        self.size(star)
            .file_size(options::CONVENTIONAL)
            .unwrap_or_else(|e| {
                error!("Failed to get human readable size string: {e}");
                "?".to_string()
            })
    }
}

#[derive(Clone, Debug)]
struct Other {
    addr: SocketAddr,
    jobs: usize,
    port_range: Option<Range<u16>>,
    listen_max: Option<u16>,
    cmd: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (limits, oidc, other) = std::env::args()
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

    let app = Router::new()
        .route("/enarx_toml_fallback", get(enarx_toml_fallback))
        .route(
            "/out",
            post(move |user| reader(user, jobs::Standard::Output)),
        )
        .route(
            "/err",
            post(move |user| reader(user, jobs::Standard::Error)),
        )
        .route(
            "/",
            get(move |user| root_get(user, limits))
                .post(move |user, mp| {
                    root_post(
                        user,
                        mp,
                        other.cmd,
                        limits,
                        other.port_range,
                        other.listen_max,
                        other.jobs,
                    )
                })
                .delete(root_delete),
        );

    let app = oidc.routes::<Data>(app).await?;

    Server::bind(&other.addr)
        .serve(app.layer(TraceLayer::new_for_http()).into_make_service())
        .await?;
    Ok(())
}

async fn root_get(user: Option<Ref<auth::User<Data>>>, limits: Limits) -> impl IntoResponse {
    let (user, star) = match user {
        None => (false, false),
        Some(user) => {
            if user.read().await.data.job().is_some() {
                return HtmlTemplate(JobTemplate).into_response();
            }

            (true, user.read().await.is_starred("enarx/enarx").await)
        }
    };

    let tmpl = IdxTemplate {
        toml: enarx_config::CONFIG_TEMPLATE,
        examples: EXAMPLES.as_slice(),
        user,
        star,
        size: limits.size(star),
        size_human: limits.size_human(star),
        ttl: limits.time_to_live(star).as_secs(),
    };

    HtmlTemplate(tmpl).into_response()
}

// TODO: create tests for endpoints: #38
async fn root_post(
    user: Ref<auth::User<Data>>,
    mut multipart: Multipart,
    command: String,
    limits: Limits,
    port_range: Option<Range<u16>>,
    listen_max: Option<u16>,
    jobs: usize,
) -> impl IntoResponse {
    let star = user.read().await.is_starred("enarx/enarx").await;
    let ttl = limits.time_to_live(star);
    let size = limits.size(star);

    if user.read().await.data.job().is_some() {
        return Err(Redirect::to("/").into_response());
    }

    if jobs::Job::count() >= jobs {
        return Err(redirect::too_many_workloads().into_response());
    }

    let mut workload_type = None;
    let mut slug = None;
    let mut wasm = None;
    let mut toml = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?
    {
        match field.name() {
            Some("workloadType") => {
                if field.content_type().is_some() {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }

                if workload_type.is_some() {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }

                workload_type = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?,
                );
            }

            Some("slug") => {
                if field.content_type().is_some() {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }

                if slug.is_some() {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }

                slug = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?,
                );
            }

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
                    if len > size {
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

    let workload_type = workload_type.ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;

    let enarx_config_string = match &toml {
        Some(toml) => read_to_string(toml).await.map_err(|e| {
            debug!("failed to read enarx config file: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?,
        None => {
            let slug = slug
                .as_ref()
                .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
            let (repo, tag) = slug
                .split_once(':')
                .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
            get_enarx_config_from_drawbridge(repo, tag)
                .await
                .map_err(|e| {
                    debug!("failed to get toml from drawbridge with tag: {}: {e}", slug);
                    StatusCode::BAD_REQUEST.into_response()
                })?
                .text()
                .await
                .map_err(|e| {
                    debug!(
                        "failed to get toml body from drawbridge response: {}: {e}",
                        slug
                    );
                    StatusCode::BAD_REQUEST.into_response()
                })?
        }
    };

    let ports = ports::get_listen_ports(&enarx_config_string).map_err(|e| {
        debug!("failed to get ports from enarx config: {e}");
        StatusCode::BAD_REQUEST.into_response()
    })?;

    if let Some(listen_max) = listen_max {
        // Check if the user is trying to listen on too many ports.
        if ports.len() > listen_max as usize {
            return Err(redirect::too_many_listeners(listen_max).into_response());
        }
    }

    if let Some(port_range) = port_range {
        // Check if the port is outside of the range of allowed ports
        let illegal_ports = ports
            .iter()
            .filter(|port| !port_range.contains(port))
            .cloned()
            .collect::<Vec<_>>();

        if !illegal_ports.is_empty() {
            return Err(redirect::illegal_ports(&illegal_ports, port_range).into_response());
        }
    }

    // Check if a port is already in use by another running workload
    ports::try_reserve(&ports)
        .await
        .map_err(|port_conflicts| redirect::port_conflicts(&port_conflicts).into_response())?;

    // Create the new job and get an identifier.
    let uuid = {
        let mut lock = user.write().await;

        if lock.data.job().is_some() {
            return Err(Redirect::to("/").into_response());
        }

        if jobs::Job::count() >= jobs {
            return Err(redirect::too_many_workloads().into_response());
        }

        let job = jobs::Job::new(command, workload_type, slug, wasm, toml, ports)?;
        let uuid = job.uuid;
        lock.data = Data::new(Some(job));
        uuid
    };

    // Set the job timeout.
    let weak = Ref::downgrade(&user);
    tokio::spawn(async move {
        sleep(ttl).await;

        if let Some(user) = weak.upgrade() {
            debug!("timeout for: {}", uuid);
            let mut lock = user.write().await;
            if lock.data.job().as_ref().map(|j| j.uuid) == Some(uuid) {
                lock.data.kill_job().await;
            }
        }
    });

    info!(
        "job started. job_id={uuid}, user_id={}",
        user.read().await.uid
    );
    Ok((StatusCode::SEE_OTHER, [("Location", "/")]))
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EnarxTomlFallbackParams {
    repo: String,
    tag: String,
}

async fn get_enarx_config_from_drawbridge(
    repo: &str,
    tag: &str,
) -> Result<reqwest::Response, reqwest::Error> {
    HTTP.get(&format!(
        "https://store.profian.com/api/v0.2.0/{repo}/_tag/{tag}/tree/Enarx.toml"
    ))
    .send()
    .await
}

async fn enarx_toml_fallback(
    _user: Ref<auth::User<Data>>,
    Query(params): Query<EnarxTomlFallbackParams>,
) -> Result<String, (StatusCode, String)> {
    let EnarxTomlFallbackParams { repo, tag } = params;
    let response = get_enarx_config_from_drawbridge(&repo, &tag).await;
    let response = response.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get Enarx.toml from repo: {e}"),
        )
    })?;
    let status_code = response.status();
    let body = response.text().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get string contents of Enarx.toml in response body: {e}"),
        )
    })?;

    match status_code {
        StatusCode::OK => Ok(body),
        StatusCode::NOT_FOUND => Err((
            StatusCode::NOT_FOUND,
            format!("Couldn\'t find file in package '{repo}' with tag '{tag}'"),
        )),
        status_code => Err((status_code, body)),
    }
}

async fn root_delete(user: Ref<auth::User<Data>>) -> StatusCode {
    let mut lock = user.write().await;

    if let Some(uuid) = lock.data.job().as_ref().map(|j| j.uuid) {
        debug!("killing: {}", uuid);
        lock.data.kill_job().await;
    }

    StatusCode::OK
}

async fn reader(user: Ref<auth::User<Data>>, kind: jobs::Standard) -> Result<Vec<u8>, StatusCode> {
    let mut buf = [0; 4096];

    match user.write().await.data.job_mut() {
        None => Err(StatusCode::NOT_FOUND),
        Some(job) => {
            let future = job.read(kind, &mut buf);
            match timeout(READ_TIMEOUT, future).await {
                Ok(Err(..)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
                Ok(Ok(size)) => Ok(buf[..size].to_vec()),
                Err(..) => Ok(Vec::new()),
            }
        }
    }
}
