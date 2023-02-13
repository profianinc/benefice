// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::Workload;

use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::ops::Range;
use std::path::Path;
use std::process::Stdio;

use anyhow::{anyhow, Context};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::future::{AbortHandle, Abortable};
use rand::RngCore;
use tokio::process::{Child, Command};
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub(crate) struct Job {
    destructor: AbortHandle,
    workload: Workload,

    pub(crate) id: String,
    pub(crate) exec: Child,
    // Host port -> (Container port, Url)
    pub(crate) mapped_ports: HashMap<u16, (u16, String)>,
}

#[cfg(target_os = "linux")]
async fn used_ports<T: FromIterator<u16>>(ss: impl AsRef<OsStr>) -> anyhow::Result<T> {
    use std::io::{BufRead, BufReader};

    let out = Command::new(ss)
        .arg("-ltnH")
        .output()
        .await
        .context("failed to run `ss`")?;
    BufReader::new(out.stdout.as_slice())
        .lines()
        .map(|s| {
            s.context("failed to read line")?
                .split_whitespace()
                .nth(3)
                .ok_or_else(|| anyhow!("address column missing"))?
                .split(':')
                .last()
                .ok_or_else(|| anyhow!("failed to parse socket address"))?
                .parse()
                .context("failed to parse port")
        })
        .collect()
}

impl Job {
    /// Spawns a new job via selected OCI engine, it is not safe for concurrent use.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::let_underscore_future)]
    pub(crate) async fn spawn(
        id: String,
        workload: Workload,
        ss_command: impl AsRef<OsStr>,
        oci_command: impl AsRef<OsStr>,
        oci_image: impl AsRef<str>,
        port_range: Range<u16>,
        ports: impl IntoIterator<Item = (u16, String)>,
        devices: impl IntoIterator<Item = impl AsRef<Path>>,
        paths: impl IntoIterator<Item = impl AsRef<Path>>,
        privileged: bool,
        destructor: impl Future<Output = ()> + Send + 'static,
    ) -> Result<Self, Response> {
        info!(job_id = id, ?workload, "spawning a job");
        let mut cmd = Command::new(&oci_command);
        let cmd = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .args(["run", "--rm", "--name", id.as_str()])
            .arg("--log-driver=none");

        let cmd = if privileged {
            cmd.arg("--privileged")
        } else {
            cmd
        };

        let cmd = devices
            .into_iter()
            .fold(cmd, |cmd, dev| cmd.arg("--device").arg(dev.as_ref()));

        let cmd = paths.into_iter().fold(cmd, |cmd, path| {
            let path = path.as_ref().display();
            cmd.args(["-v", &format!("{path}:{path}")])
        });

        let cmd = env::var_os("ENARX_BACKEND")
            .into_iter()
            .fold(cmd, |cmd, backend| {
                let mut var = OsString::from("ENARX_BACKEND=");
                var.push(backend);
                cmd.arg("-e").arg(var)
            });

        let ports: Vec<_> = ports.into_iter().collect();
        let port_count = ports.len();

        let mapped_ports = if port_count > 0 {
            let used: HashSet<_> = used_ports(ss_command).await.map_err(|e| {
                error!(error = ?e, "failed to lookup used ports");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
            let start = port_range.start
                + (rand::thread_rng().next_u32() as usize % port_range.len()) as u16;
            let mapped: HashMap<_, _> = (start..port_range.end)
                .chain(port_range.start..start)
                .into_iter()
                .filter(|p| !used.contains(p))
                .zip(ports)
                .collect();
            if mapped.len() < port_count {
                warn!("insufficient amount of open ports");
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Insufficient amount of open ports on the system, try again later",
                )
                    .into_response());
            }
            mapped
        } else {
            Default::default()
        };
        let cmd = mapped_ports.iter().fold(cmd, |cmd, (host, (cont, _))| {
            cmd.arg("-p").arg(format!("{host}:{cont}"))
        });

        let cmd = match &workload {
            Workload::Drawbridge { slug } => {
                cmd.args([oci_image.as_ref(), "enarx", "deploy", slug.as_str()])
            }
            Workload::Upload { wasm, conf } => cmd.args([
                "-v",
                &format!("{}:/app/Enarx.toml", conf.path().display()),
                "-v",
                &format!("{}:/app/main.wasm", wasm.path().display()),
                oci_image.as_ref(),
                "enarx",
                "run",
                "--wasmcfgfile",
                "/app/Enarx.toml",
                "/app/main.wasm",
            ]),
        };
        debug!(?cmd, "spawning a job run command");
        let exec = cmd.spawn().map_err(|e| {
            error!(error = ?e, "failed to start job");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

        let (destructor_tx, destructor_rx) = AbortHandle::new_pair();
        _ = tokio::spawn(Abortable::new(destructor, destructor_rx));
        Ok(Self {
            id,
            exec,
            mapped_ports,
            workload,
            destructor: destructor_tx,
        })
    }

    pub(crate) async fn kill(mut self) {
        self.destructor.abort();
        if let Err(e) = self.exec.kill().await {
            error!(error = ?e, job_id = self.id, "failed to kill job");
        }
        if let Workload::Upload { wasm, conf } = self.workload {
            debug!("closing `main.wasm`");
            if let Err(e) = wasm.close() {
                error!(error = ?e, job_id = self.id, "failed to close `main.wasm`");
            };
            debug!("closing `Enarx.toml`");
            if let Err(e) = conf.close() {
                error!(error = ?e, job_id = self.id, "failed to close `Enarx.toml`");
            };
        }
    }
}
