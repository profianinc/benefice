// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    absolute_paths_not_starting_with_crate,
    deprecated_in_future,
    missing_copy_implementations,
    missing_debug_implementations,
    noop_method_call,
    rust_2018_compatibility,
    rust_2018_idioms,
    rust_2021_compatibility,
    single_use_lifetimes,
    trivial_bounds,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_code,
    unreachable_patterns,
    unreachable_pub,
    unstable_features,
    unused,
    unused_crate_dependencies,
    unused_import_braces,
    unused_lifetimes,
    unused_results,
    variant_size_differences
)]

mod auth;
mod job;
mod jobs;
mod ports;
mod secret;
mod templates;

use self::auth::{Key, User};
use self::job::{Job, Standard};
use self::jobs::Jobs;

use crate::templates::{HtmlTemplate, IdxTemplate, Page};

use std::ffi::OsString;
use std::fs::read;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::time::Duration;

use axum::extract::Multipart;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router, Server};

use anyhow::{bail, Context as _};
use clap::Parser;
use humansize::{file_size_opts as options, FileSize};
use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use reqwest::{Client, ClientBuilder};
use serde_json::json;
use tokio::fs::read_to_string;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

static HTTP: Lazy<Client> = Lazy::new(|| {
    const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
    ClientBuilder::new().user_agent(USER_AGENT).build().unwrap()
});

static JOBS: Lazy<RwLock<Jobs>> = Lazy::new(Default::default);

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
    /// Defaults to 16x the number of cores on the system.
    #[clap(long, default_value_t = num_cpus::get() * 16)]
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

    /// The lowest listen port to be allocated via the selected OCI container engine.
    #[clap(long, default_value_t = 0)]
    port_min: u16,

    /// The highest listen port to be allocated via the selected OCI container engine.
    #[clap(long, default_value_t = 0)]
    port_max: u16,

    /// The maximum number of listen ports a workload is allowed to have (0 to disable).
    #[clap(long, default_value_t = 0)]
    listen_max: u16,

    /// OCI container engine command to execute, for example, `docker` or `podman`.
    /// This may also be an absolute path.
    #[clap(long, default_value = "docker")]
    oci_command: OsString,

    /// OCI image tag to use.
    /// Defaults to the last tested image from https://hub.docker.com/r/enarx/enarx
    #[clap(long, default_value = "enarx/enarx:0.6.3")]
    oci_image: OsString,

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
            session_ttl: Duration::from_secs(self.session_ttl * 60),
            session_key: self.session_key.map(|k| k.into()).unwrap_or_default(),
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
            oci_command: self.oci_command,
            oci_image_tag: self.oci_image,
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
    fn time_to_live(&self, star: bool) -> Duration {
        if star {
            self.timeout_default
        } else {
            self.timeout_starred
        }
    }

    /// Get the maximum allowed wasm size in bytes.
    fn size(&self, star: bool) -> usize {
        let size_megabytes = if star {
            self.size_limit_default
        } else {
            self.size_limit_starred
        };
        size_megabytes * 1024 * 1024
    }

    fn size_human(&self, star: bool) -> String {
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
    oci_command: OsString,
    oci_image_tag: OsString,
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
        .route("/out", post(move |user| reader(user, Standard::Output)))
        .route("/err", post(move |user| reader(user, Standard::Error)))
        .route(
            "/drawbridge",
            get(move |user| root_get(user, limits, Page::Drawbridge)),
        )
        .route(
            "/upload",
            get(move |user| root_get(user, limits, Page::Upload)),
        )
        .route(
            "/",
            get(move |user| root_get(user, limits, Page::Examples))
                .post(move |user, mp| {
                    root_post(
                        user,
                        mp,
                        limits,
                        other.port_range,
                        other.listen_max,
                        other.jobs,
                        other.oci_command,
                        other.oci_image_tag,
                    )
                })
                .delete(root_delete),
        );

    let app = oidc.routes(app).await?;

    Server::bind(&other.addr)
        .serve(app.layer(TraceLayer::new_for_http()).into_make_service())
        .await?;
    Ok(())
}

async fn root_get(user: Option<User>, limits: Limits, page: Page) -> impl IntoResponse {
    let (user, star) = match user {
        None => (false, false),
        Some(user) => (true, user.is_starred("enarx/enarx").await),
    };

    let tmpl = IdxTemplate {
        page,
        toml: enarx_config::CONFIG_TEMPLATE,
        examples: EXAMPLES.as_slice(),
        user,
        star,
        _size: limits.size(star),
        size_human: limits.size_human(star),
        ttl: limits.time_to_live(star).as_secs(),
    };

    HtmlTemplate(tmpl).into_response()
}

// TODO: create tests for endpoints: #38
#[allow(clippy::too_many_arguments)]
async fn root_post(
    user: Option<User>,
    mut multipart: Multipart,
    limits: Limits,
    port_range: Option<Range<u16>>,
    listen_max: Option<u16>,
    jobs: usize,
    oci_command: OsString,
    oci_image_tag: OsString,
) -> impl IntoResponse {
    let user = match user {
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "You are not authenticated. Please login.",
            )
                .into_response())
        }
        Some(user) => user,
    };

    let star = user.is_starred("enarx/enarx").await;
    let ttl = limits.time_to_live(star);
    let size = limits.size(star);

    if let Some(uuid) = JOBS.write().await.remove(&user).await {
        debug!("replacing an old job with a new one: {}", uuid);
    }

    let mut workload_type = None;
    let mut slug = None;
    let mut ports = None;
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

            Some("ports") => {
                if field.content_type().is_some() {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }

                if ports.is_some() {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }

                ports = Some(
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

    fn get_toml_ports(toml: &str) -> Result<Vec<u16>, Response> {
        ports::get_listen_ports(toml).map_err(|e| {
            debug!("failed to get ports from enarx config: {e}");
            StatusCode::BAD_REQUEST.into_response()
        })
    }

    let ports = match (&ports, &toml) {
        (_, Some(toml)) => {
            let toml = read_to_string(toml).await.map_err(|e| {
                debug!("failed to read enarx config file: {e}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
            get_toml_ports(&toml).map_err(|e| e.into_response())?
        }
        (None, None) => {
            let slug = slug
                .as_ref()
                .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
            let (repo, tag) = slug
                .split_once(':')
                .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
            let toml = get_enarx_config_from_drawbridge(repo, tag)
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
                })?;
            get_toml_ports(&toml).map_err(|e| e.into_response())?
        }
        (Some(ports), None) => {
            let mut parsed_ports = vec![];

            for port in ports
                .replace(',', " ")
                .split(' ')
                .filter(|port| !port.is_empty())
                .map(|port| port.to_string())
            {
                let port = port.parse::<u16>().map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid port specified: {port}: {e}"),
                    )
                        .into_response()
                })?;
                parsed_ports.push(port);
            }

            parsed_ports
        }
    };

    if let Some(listen_max) = listen_max {
        // Check if the user is trying to listen on too many ports.
        if ports.len() > listen_max as usize {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Your workload is using too many listeners (more than {listen_max})"),
            )
                .into_response());
        }
    }

    // Check if a port is already in use by another running workload
    let mapped_ports = ports::try_reserve(ports, &port_range).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Failed to find free ports for your workload, try again later",
        )
            .into_response()
    })?;

    // Create the new job.
    let uuid = Uuid::new_v4();
    {
        if JOBS.read().await.by_user(&user).is_some() {
            return Err(Redirect::to("/").into_response());
        }

        if JOBS.read().await.count() >= jobs {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many workloads are running right now, try again later",
            )
                .into_response());
        }

        let job = Job::new(
            oci_image_tag,
            workload_type,
            slug,
            wasm,
            toml,
            oci_command,
            mapped_ports.clone(),
        )?;
        JOBS.write().await.insert(user, job);
    }

    // Set the job timeout.
    _ = tokio::spawn(async move {
        sleep(ttl).await;

        if let Some(uuid) = JOBS.write().await.remove(&user).await {
            debug!("timeout for: {}", uuid);
        }
    });

    info!("job started. job_id={uuid}, user_id={user}");

    let json = json!({ "ports": mapped_ports });
    Ok(Json(json))
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

async fn root_delete(user: User) -> StatusCode {
    if let Some(uuid) = JOBS.write().await.remove(&user).await {
        debug!("killing: {}", uuid);
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
