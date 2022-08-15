use std::process::Stdio;
use std::str::FromStr;

use anyhow::anyhow;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tracing::{debug, error};

#[derive(Debug)]
pub(crate) enum WorkloadType {
    Drawbridge,
    Browser,
}

impl FromStr for WorkloadType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "drawbridge" => WorkloadType::Drawbridge,
            "browser" => WorkloadType::Browser,
            _ => return Err(anyhow!("Unknown workload type {s}")),
        })
    }
}

pub(crate) enum Standard {
    Output,
    Error,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct Job {
    exec: Child,
    workload_type: WorkloadType,
    slug: Option<String>,
    wasm: Option<NamedTempFile>,
    toml: Option<NamedTempFile>,
    reserved_ports: Vec<u16>,
}

impl Drop for Job {
    fn drop(&mut self) {
        if !self.reserved_ports.is_empty() {
            error!("a job was not cleaned up correctly");
        }
    }
}

impl Job {
    pub(crate) fn new(
        cmd: String,
        workload_type: String,
        slug: Option<String>,
        wasm: Option<NamedTempFile>,
        toml: Option<NamedTempFile>,
        reserved_ports: Vec<u16>,
    ) -> Result<Self, Response> {
        let workload_type = WorkloadType::from_str(&workload_type).map_err(|e| {
            debug!("Failed to parse workload type: {e}");
            StatusCode::BAD_REQUEST.into_response()
        })?;

        let exec = match workload_type {
            WorkloadType::Drawbridge => {
                let slug = slug
                    .as_ref()
                    .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
                Command::new(cmd)
                    .arg("deploy")
                    .arg(slug)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()
                    .map_err(|e| {
                        error!("failed to spawn process: {e}");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    })?
            }
            WorkloadType::Browser => {
                let wasm = wasm
                    .as_ref()
                    .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
                let toml = toml
                    .as_ref()
                    .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
                Command::new(cmd)
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
                    })?
            }
        };

        Ok(Self {
            exec,
            workload_type,
            slug,
            wasm,
            toml,
            reserved_ports,
        })
    }

    pub(crate) async fn read(
        &mut self,
        kind: Standard,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        match kind {
            Standard::Output => self.exec.stdout.as_mut().unwrap().read(buffer).await,
            Standard::Error => self.exec.stderr.as_mut().unwrap().read(buffer).await,
        }
    }
}
