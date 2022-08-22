// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::ports;
use crate::ENARX_OCI_IMAGE_TAG;

use std::collections::HashMap;
use std::ffi::OsString;
use std::process::Stdio;
use std::str::FromStr;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use anyhow::anyhow;
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tracing::{debug, error};
use uuid::Uuid;

#[derive(Debug)]
pub(crate) enum WorkloadType {
    Drawbridge,
    Upload,
}

impl FromStr for WorkloadType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "drawbridge" => WorkloadType::Drawbridge,
            "upload" => WorkloadType::Upload,
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
    pub(crate) uuid: Uuid,
    exec: Child,
    workload_type: WorkloadType,
    slug: Option<String>,
    wasm: Option<NamedTempFile>,
    toml: Option<NamedTempFile>,

    /// OCI container engine command
    oci_command: OsString,
    mapped_ports: HashMap<u16, u16>,
}

impl Drop for Job {
    fn drop(&mut self) {
        if !self.mapped_ports.is_empty() {
            error!("a job was not cleaned up correctly");
        }
    }
}

impl Job {
    pub(crate) fn new(
        workload_type: String,
        slug: Option<String>,
        wasm: Option<NamedTempFile>,
        toml: Option<NamedTempFile>,
        oci_command: OsString,
        mapped_ports: HashMap<u16, u16>,
    ) -> Result<Self, Response> {
        let uuid = Uuid::new_v4();
        let workload_type = WorkloadType::from_str(&workload_type).map_err(|e| {
            debug!("Failed to parse workload type: {e}");
            StatusCode::BAD_REQUEST.into_response()
        })?;
        let mapped_ports_args = mapped_ports
            .iter()
            .flat_map(|(container_port, host_port)| {
                ["-p".to_string(), format!("{host_port}:{container_port}")]
            })
            .collect::<Vec<_>>();
        let exec = match workload_type {
            WorkloadType::Drawbridge => {
                let slug = slug
                    .as_ref()
                    .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
                Command::new(&oci_command)
                    .args(&["run", "--rm", "--name"])
                    .arg(&uuid.to_string())
                    .args(mapped_ports_args)
                    .arg(ENARX_OCI_IMAGE_TAG)
                    .arg("enarx")
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
            WorkloadType::Upload => {
                let wasm = wasm
                    .as_ref()
                    .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
                let wasm_path_str = wasm.path().to_str().ok_or_else(|| {
                    error!("Failed to get wasm path as str");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
                let toml = toml
                    .as_ref()
                    .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
                let toml_path_str = toml.path().to_str().ok_or_else(|| {
                    error!("Failed to get toml path as str");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
                Command::new(&oci_command)
                    .args(&["run", "--rm", "--name"])
                    .arg(&uuid.to_string())
                    .arg("-v")
                    .arg(format!("{}:/app/Enarx.toml", toml_path_str))
                    .arg("-v")
                    .arg(format!("{}:/app/main.wasm", wasm_path_str))
                    .args(mapped_ports_args)
                    .arg(ENARX_OCI_IMAGE_TAG)
                    .arg("enarx")
                    .arg("run")
                    .arg("--wasmcfgfile")
                    .arg("/app/Enarx.toml")
                    .arg("/app/main.wasm")
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
            uuid,
            exec,
            workload_type,
            slug,
            wasm,
            toml,
            oci_command,
            mapped_ports,
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

    pub(crate) async fn kill(&mut self) {
        match Command::new(&self.oci_command)
            .arg("kill")
            .arg(&self.uuid.to_string())
            .spawn()
        {
            Err(e) => {
                error!("failed to run docker kill {}", e);
            }
            Ok(mut child) => {
                if let Err(e) = child.wait().await {
                    error!("failed to run docker kill {}", e);
                }
            }
        }
        let _ = self.exec.kill().await;
        ports::free(&self.mapped_ports).await;
        self.mapped_ports.clear();
    }
}
