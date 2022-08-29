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
mod secret;
mod templates;

use self::auth::{Key, User};
use self::job::Job;
use self::templates::{HtmlTemplate, IdxTemplate, Page};

use std::collections::HashMap;
use std::env::temp_dir;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use axum::extract::multipart::Field;
use axum::extract::{Multipart, Path as AxumPath};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, Server};
use axum_extra::extract::CookieJar;
use clap::Parser;
use confargs::{args, prefix_char_filter, Toml};
use enarx_config::{Config, File, Protocol};
use futures_util::{stream, StreamExt};
use humansize::{file_size_opts as options, FileSize};
use once_cell::sync::Lazy;
use serde_json::json;
use tempfile::NamedTempFile;
use tokio::fs::read_to_string;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};
use tower_http::{
    trace::{
        DefaultMakeSpan, DefaultOnBodyChunk, DefaultOnEos, DefaultOnFailure, DefaultOnRequest,
        DefaultOnResponse, TraceLayer,
    },
    LatencyUnit,
};
use tracing::{debug, error, info, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

// TODO: raise this when this is fixed: https://github.com/profianinc/benefice/issues/75
const READ_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum size of Enarx.toml in bytes
const MAX_CONF_SIZE: usize = 256 * 1024; // 256 KiB

/// Active jobs
static JOBS: Lazy<RwLock<HashMap<User, RwLock<Job>>>> = Lazy::new(Default::default);

/// Predefined examples
static EXAMPLES: Lazy<Vec<&'static str>> = Lazy::new(|| {
    include_str!("../examples.txt")
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
});

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

    /// Externally accessible domain name for serving demos.
    /// This should not be the same as the benefice server URL for security reasons.
    /// For example: demo.example.com
    #[clap(long)]
    demo_fqdn: String,

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
    #[clap(long, default_value_t = 1024)]
    port_min: u16,

    /// The highest listen port to be allocated via the selected OCI container engine.
    #[clap(long, default_value_t = 65535)]
    port_max: u16,

    /// The maximum number of listen ports a workload is allowed to have (0 to disable).
    #[clap(long, default_value_t = 0)]
    listen_max: u16,

    /// `ss` command to execute, for example `ss`.
    #[clap(long, default_value = "ss")]
    ss_command: OsString,

    /// OCI container engine command to execute, for example, `docker` or `podman`.
    /// This may also be an absolute path.
    #[clap(long, default_value = "docker")]
    oci_command: OsString,

    /// OCI image to use.
    /// Defaults to the last tested image from https://hub.docker.com/r/enarx/enarx
    #[clap(long, default_value = "enarx/enarx:0.6.3")]
    oci_image: String,

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

    /// Runtime directory, where uploaded workloads and configs will be temporarily stored.
    #[clap(long, default_value_os_t = temp_dir())]
    runtime_dir: PathBuf,

    /// Devices to expose to the container.
    #[clap(long)]
    devices: Vec<PathBuf>,

    /// Paths to expose to the container.
    /// Usually, this would be `/var/run/aesmd/aesm.socket` on Intel SGX and `/var/cache/amd-sev` on AMD SEV.
    #[clap(long)]
    paths: Vec<PathBuf>,

    /// Whether to run the container in privileged mode.
    #[clap(long)]
    privileged: bool,
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
            demo_fqdn: self.demo_fqdn,
            addr: self.addr,
            jobs_max: self.jobs,
            port_range: self.port_min..self.port_max,
            listen_max: if self.listen_max == 0 {
                None
            } else {
                Some(self.listen_max)
            },
            ss_command: self.ss_command,
            oci_command: self.oci_command,
            oci_image: self.oci_image,
            runtime_dir: self.runtime_dir,
            devices: self.devices,
            paths: self.paths,
            privileged: self.privileged,
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
    demo_fqdn: String,
    addr: SocketAddr,
    jobs_max: usize,
    port_range: Range<u16>,
    listen_max: Option<u16>,
    ss_command: OsString,
    oci_command: OsString,
    oci_image: String,
    runtime_dir: PathBuf,
    devices: Vec<PathBuf>,
    paths: Vec<PathBuf>,
    privileged: bool,
}

async fn read_chunk(mut rdr: impl AsyncRead + Unpin) -> Result<Vec<u8>, StatusCode> {
    let mut buf = [0; 4096];
    match timeout(READ_TIMEOUT, rdr.read(&mut buf)).await {
        Ok(Err(e)) => {
            error!("failed to read chunk: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Ok(Ok(size)) => Ok(buf[..size].to_vec()),
        Err(..) => Ok(Vec::new()),
    }
}

async fn read_stdout(AxumPath(id): AxumPath<String>, user: User) -> Result<Vec<u8>, StatusCode> {
    if let Some(job) = JOBS.read().await.get(&user) {
        let mut lock = job.write().await;

        if lock.id != id {
            // The client is requesting a job that doesn't exist.
            return Err(StatusCode::NOT_FOUND);
        }

        if let Some(stdout) = lock.exec.stdout.as_mut() {
            read_chunk(stdout).await
        } else {
            error!("job is missing STDOUT. user_id=`{user}`");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn read_stderr(AxumPath(id): AxumPath<String>, user: User) -> Result<Vec<u8>, StatusCode> {
    if let Some(job) = JOBS.read().await.get(&user) {
        let mut lock = job.write().await;

        if lock.id != id {
            // The client is requesting a job that doesn't exist.
            return Err(StatusCode::NOT_FOUND);
        }

        if let Some(stdout) = lock.exec.stderr.as_mut() {
            read_chunk(stdout).await
        } else {
            error!("job is missing STDERR. user_id=`{user}`");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (limits, oidc, other) = args::<Toml>(prefix_char_filter::<'@'>)
        .context("Failed to parse config")
        .map(Args::parse_from)?
        .split();

    let tracing_registry = tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::new(
        std::env::var("RUST_LOG")
            .unwrap_or_else(|_| "example_tracing_aka_logging=debug,tower_http=debug".into()),
    ));
    if std::env::var("RUST_LOG_JSON").is_ok() {
        tracing_registry
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_registry
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    let app = Router::new()
        .route("/out/:id", post(read_stdout))
        .route("/err/:id", post(read_stderr))
        .route(
            "/drawbridge",
            get({
                let demo_fqdn = other.demo_fqdn.clone();
                move |user| root_get(user, limits, Page::Drawbridge, demo_fqdn)
            }),
        )
        .route(
            "/upload",
            get({
                let demo_fqdn = other.demo_fqdn.clone();
                move |user| root_get(user, limits, Page::Upload, demo_fqdn)
            }),
        )
        .route(
            "/",
            get({
                let demo_fqdn = other.demo_fqdn.clone();
                move |user| root_get(user, limits, Page::Examples, demo_fqdn)
            })
            .post(move |user, mp| {
                root_post(
                    user,
                    mp,
                    limits,
                    other.port_range,
                    other.listen_max,
                    other.jobs_max,
                    other.ss_command,
                    other.oci_command,
                    other.oci_image,
                    other.runtime_dir,
                    other.devices,
                    other.paths,
                    other.privileged,
                )
            })
            .delete(root_delete),
        );

    let app = oidc.routes(app).await?;
    let app = app.layer(
        TraceLayer::new_for_http()
            .make_span_with(
                DefaultMakeSpan::new()
                    .level(Level::INFO)
                    .include_headers(true),
            )
            .on_request(DefaultOnRequest::new().level(Level::INFO))
            .on_response(
                DefaultOnResponse::new()
                    .level(Level::INFO)
                    .latency_unit(LatencyUnit::Micros),
            )
            .on_body_chunk(DefaultOnBodyChunk::new())
            .on_eos(
                DefaultOnEos::new()
                    .level(Level::INFO)
                    .latency_unit(LatencyUnit::Micros),
            )
            .on_failure(
                DefaultOnFailure::new()
                    .level(Level::INFO)
                    .latency_unit(LatencyUnit::Micros),
            ),
    );

    Server::bind(&other.addr)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn root_get(
    user: Option<User>,
    limits: Limits,
    page: Page,
    demo_fqdn: String,
) -> impl IntoResponse {
    let (user, star) = match user {
        None => (false, false),
        Some(user) => (true, user.has_starred_enarx()),
    };

    let tmpl = IdxTemplate {
        demo_fqdn,
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

#[inline]
async fn parse_string_field(field: Field<'_>) -> Result<String, Response> {
    if field.content_type().is_some() {
        return Err(StatusCode::BAD_REQUEST.into_response());
    }
    field
        .text()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())
}

#[inline]
async fn parse_file_field(
    mut field: Field<'_>,
    max_size: usize,
    runtime_dir: impl AsRef<Path>,
) -> Result<NamedTempFile, Response> {
    let mut len = 0;
    let mut out = NamedTempFile::new_in(runtime_dir).map_err(|e| {
        error!("failed to create a new temporary file: {e}");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?
    {
        len += chunk.len();
        if len > max_size {
            return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
        }

        out.write_all(&chunk).map_err(|e| {
            error!("failed to write chunk to temporary file: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
    }
    Ok(out)
}

#[inline]
fn listen_ports<T: FromIterator<u16>>(conf: Config) -> T {
    conf.files
        .into_iter()
        .filter_map(|file| match file {
            File::Null { .. }
            | File::Stdin { .. }
            | File::Stdout { .. }
            | File::Stderr { .. }
            | File::Connect { .. } => None,
            File::Listen { port, prot, .. } => match prot {
                Protocol::Tls | Protocol::Tcp => Some(port),
            },
        })
        .collect()
}

#[inline]
async fn last_page(jar: &CookieJar) -> Option<&str> {
    jar.get("LAST_PATH").map(|cookie| cookie.value())
}

#[derive(Debug)]
pub enum Workload {
    Drawbridge {
        slug: String,
    },
    Upload {
        wasm: NamedTempFile,
        conf: NamedTempFile,
    },
}

// TODO: create tests for endpoints: #38
#[allow(clippy::too_many_arguments)]
async fn root_post(
    user: Option<User>,
    mut multipart: Multipart,
    limits: Limits,
    port_range: Range<u16>,
    listen_max: Option<u16>,
    jobs_max: usize,
    ss_command: impl AsRef<OsStr>,
    oci_command: impl AsRef<OsStr>,
    oci_image: impl AsRef<str>,
    runtime_dir: impl AsRef<Path>,
    devices: impl IntoIterator<Item = impl AsRef<Path>>,
    paths: impl IntoIterator<Item = impl AsRef<Path>>,
    privileged: bool,
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

    let star = user.has_starred_enarx();
    let ttl = limits.time_to_live(star);
    let max_wasm_size = limits.size(star);

    let mut workload_type = None;
    let mut slug = None;
    let mut wasm = None;
    let mut conf = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?
    {
        match field.name() {
            Some("workloadType") if workload_type.is_none() => {
                workload_type = parse_string_field(field).await?.into()
            }
            Some("slug") if slug.is_none() => slug = parse_string_field(field).await?.into(),
            Some("wasm") if wasm.is_none() => match field.content_type() {
                None => return Err(StatusCode::BAD_REQUEST.into_response()),
                Some("application/wasm") => {
                    wasm = parse_file_field(field, max_wasm_size, &runtime_dir)
                        .await?
                        .into()
                }
                _ => return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()),
            },
            Some("toml") if conf.is_none() && field.content_type().is_none() => {
                conf = parse_file_field(field, MAX_CONF_SIZE, &runtime_dir)
                    .await?
                    .into()
            }
            _ => return Err(StatusCode::BAD_REQUEST.into_response()),
        }
    }

    let workload = match workload_type
        .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?
        .as_str()
    {
        "upload" => Workload::Upload {
            wasm: wasm.ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?,
            conf: conf.ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?,
        },
        "drawbridge" => Workload::Drawbridge {
            slug: slug.ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?,
        },
        typ => {
            error!("Unknown workload type `{typ}`");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    };

    let ports: Vec<u16> = match &workload {
        Workload::Upload { conf, .. } => read_to_string(conf)
            .await
            .map_err(|e| {
                error!("failed to read uploaded Enarx.toml: {e}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })
            .map(|conf| toml::from_str(&conf))?
            .map(listen_ports)
            .map_err(|e| {
                debug!("failed to parse uploaded Enarx.toml: {e}");
                StatusCode::BAD_REQUEST.into_response()
            })?,
        Workload::Drawbridge { slug } => {
            let (repo, tag) = slug
                .split_once(':')
                .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
            match reqwest::get(format!(
                "https://store.profian.com/api/v0.2.0/{repo}/_tag/{tag}/tree/Enarx.toml"
            ))
            .await
            {
                Ok(resp) => resp
                    .text()
                    .await
                    .map_err(|e| {
                        error!("failed to read Enarx.toml for `{slug}`: {e}");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    })
                    .map(|conf| toml::from_str(&conf))?
                    .map(listen_ports)
                    .map_err(|e| {
                        debug!("failed to parse Enarx.toml for `{slug}`: {e}");
                        StatusCode::BAD_REQUEST.into_response()
                    })?,
                Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => vec![],
                Err(e) => {
                    debug!("failed to request Enarx.toml for `{slug}`: {e}");
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }
            }
        }
    };

    if let Some(listen_max) = listen_max {
        // Check if the user is trying to listen on too many ports.
        if ports.len() > listen_max as _ {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Your workload listens on {} ports, which exceeds the maximum of {listen_max}",
                    ports.len(),
                ),
            )
                .into_response());
        }
    }

    let mut jobs = JOBS.write().await;

    if jobs.len() >= jobs_max
        && stream::iter(jobs.values())
            .filter(|job| async { matches!(job.write().await.exec.try_wait(), Ok(None)) })
            .count()
            .await
            >= jobs_max
    {
        // TODO: Queue the workload for execution in FIFO fashion
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many workloads are running right now, try again later",
        )
            .into_response());
    }

    // Spawn a new job.
    let id = Uuid::new_v4().to_string();
    let job = Job::spawn(
        id.clone(),
        workload,
        ss_command,
        oci_command,
        oci_image.as_ref(),
        port_range,
        ports,
        devices,
        paths,
        privileged,
        // Ensure job is killed after a timeout.
        async move {
            sleep(ttl).await;

            let mut jobs = JOBS.write().await;
            match jobs.get(&user) {
                Some(job) if job.read().await.id == id => {
                    debug!("killing job after timeout. job_id=`{id}`");
                    jobs.remove(&user).unwrap().into_inner().kill().await;
                }
                _ => {}
            }
        },
    )
    .await?;
    let resp = Json(json!({
        "id": job.id,
        "ports": job.mapped_ports
    }));
    info!("job started. job_id=`{}`, user_id=`{user}`", job.id);

    if let Some(old) = jobs.insert(user, RwLock::new(job)) {
        let old = old.into_inner();
        debug!("killing the old job. user_id=`{user}` job_id=`{}`", old.id);
        old.kill().await;
    }
    Ok(resp)
}

async fn root_delete(user: User) {
    if let Some(job) = JOBS.write().await.remove(&user) {
        let job = job.into_inner();
        debug!("explicitly killing job. user_id=`{user}` job_id={}", job.id);
        job.kill().await;
    }
}
