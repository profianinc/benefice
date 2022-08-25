// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::Workload;

use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::ops::Range;
use std::process::Stdio;

use anyhow::{anyhow, Context};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::future::{AbortHandle, Abortable};
use rand::RngCore;
use tokio::process::{Child, Command};
use tracing::{debug, error};

#[derive(Debug)]
pub(crate) struct Job {
    destructor: AbortHandle,
    workload: Workload,

    pub(crate) id: String,
    pub(crate) exec: Child,
    pub(crate) mapped_ports: HashMap<u16, u16>,
}

#[cfg(target_os = "linux")]
async fn used_ports<T: FromIterator<u16>>(ss: impl AsRef<OsStr>) -> anyhow::Result<T> {
    use std::io::{BufRead, BufReader};
    use std::net::{Ipv4Addr, SocketAddr};

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
                .replace('*', &Ipv4Addr::UNSPECIFIED.to_string())
                .parse()
                .context("failed to parse socket address")
                .map(|addr| match addr {
                    SocketAddr::V4(addr) => addr.port(),
                    SocketAddr::V6(addr) => addr.port(),
                })
        })
        .collect()
}

impl Job {
    /// Spawns a new job via selected OCI engine, it is not safe for concurrent use.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn spawn(
        id: String,
        workload: Workload,
        ss_command: impl AsRef<OsStr>,
        oci_command: OsString,
        oci_image: &str,
        port_range: Range<u16>,
        ports: impl IntoIterator<Item = u16>,
        destructor: impl Future<Output = ()> + Send + 'static,
    ) -> Result<Self, Response> {
        debug!("spawning a job. id={id} workload={:?}", workload);
        let mut cmd = Command::new(&oci_command);
        let mut cmd = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .args(["run", "--rm", "--name", id.as_str()]);

        if let Some(backend) = env::var_os("ENARX_BACKEND") {
            let mut var = OsString::from("ENARX_BACKEND=");
            var.push(backend);
            cmd = cmd.arg("-e").arg(var);
        }

        let ports: Vec<_> = ports.into_iter().collect();
        let port_count = ports.len();
        let mapped_ports = if port_count > 0 {
            let used: HashSet<_> = used_ports(ss_command).await.map_err(|e| {
                error!("failed to lookup used ports: {e}");
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
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Insufficient amount of open ports on the system, try again later",
                )
                    .into_response());
            }
            cmd = mapped.iter().fold(cmd, |cmd, (host, cont)| {
                cmd.arg("-p").arg(format!("{host}:{cont}"))
            });
            mapped
        } else {
            Default::default()
        };

        let cmd = match &workload {
            Workload::Drawbridge { slug } => {
                cmd.args([oci_image, "enarx", "deploy", slug.as_str()])
            }
            Workload::Upload { wasm, conf } => cmd.args([
                "-v",
                format!("{}:/app/Enarx.toml", conf.path().to_string_lossy()).as_str(),
                "-v",
                format!("{}:/app/main.wasm", wasm.path().to_string_lossy()).as_str(),
                oci_image,
                "enarx",
                "run",
                "--wasmcfgfile",
                "/app/Enarx.toml",
                "/app/main.wasm",
            ]),
        };
        debug!("spawning a job run command. cmd={:?}", cmd);
        let exec = cmd.spawn().map_err(|e| {
            error!("failed to start job: {e}");
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
            error!("failed to kill job: {e} job_id={}", self.id);
        }
        if let Workload::Upload { wasm, conf } = self.workload {
            debug!("closing `main.wasm`");
            if let Err(e) = wasm.close() {
                error!("failed to close `main.wasm`: {e}. job_id={}", self.id);
            };
            debug!("closing `Enarx.toml`");
            if let Err(e) = conf.close() {
                error!("failed to close `Enarx.toml`: {e}. job_id={}", self.id);
            };
        }
    }
}
