// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::drawbridge::Slug;
use crate::ports;

use std::io::Write;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use anyhow::anyhow;
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tracing::{debug, error};
use uuid::Uuid;

static COUNT: AtomicUsize = AtomicUsize::new(0);

fn enarx_deploy(cmd: &str, slug: &str) -> Result<Child, Response> {
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
        })
}

fn enarx_run(cmd: &str, toml: &NamedTempFile, wasm: &NamedTempFile) -> Result<Child, Response> {
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
        })
}

#[derive(Debug)]
pub enum WorkloadType {
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

pub enum Standard {
    Output,
    Error,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Job {
    pub uuid: Uuid,
    exec: Child,
    workload_type: WorkloadType,
    slug: Option<String>,
    wasm: Option<NamedTempFile>,
    toml: Option<NamedTempFile>,
    reserved_ports: Vec<u16>,
}

impl Drop for Job {
    fn drop(&mut self) {
        COUNT.fetch_sub(1, Ordering::SeqCst);

        if !self.reserved_ports.is_empty() {
            error!("a job was not cleaned up correctly");
        }
    }
}

impl Job {
    pub fn count() -> usize {
        COUNT.load(Ordering::SeqCst)
    }

    pub async fn new<'a>(
        cmd: String,
        workload_type: String,
        slug: Option<String>,
        mut wasm: Option<NamedTempFile>,
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

                match &toml {
                    None => enarx_deploy(&cmd, slug)?,
                    Some(toml) => {
                        let slug = Slug::new(slug.clone())
                            .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
                        let wasm_bytes = slug
                            .read("main.wasm")
                            .await
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
                            .bytes()
                            .await
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
                        let mut new_wasm = tempfile::NamedTempFile::new()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
                        new_wasm
                            .write_all(&wasm_bytes)
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
                        let child = enarx_run(&cmd, toml, &new_wasm)?;
                        wasm = Some(new_wasm);
                        child
                    }
                }
            }
            WorkloadType::Browser => {
                let wasm = wasm
                    .as_ref()
                    .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
                let toml = toml
                    .as_ref()
                    .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;
                enarx_run(&cmd, toml, wasm)?
            }
        };

        COUNT.fetch_add(1, Ordering::SeqCst);

        Ok(Self {
            uuid: Uuid::new_v4(),
            exec,
            workload_type,
            slug,
            wasm,
            toml,
            reserved_ports,
        })
    }

    pub async fn read(&mut self, kind: Standard, buffer: &mut [u8]) -> std::io::Result<usize> {
        match kind {
            Standard::Output => self.exec.stdout.as_mut().unwrap().read(buffer).await,
            Standard::Error => self.exec.stderr.as_mut().unwrap().read(buffer).await,
        }
    }

    pub async fn kill(&mut self) {
        let _ = self.exec.kill().await;
        ports::free(&self.reserved_ports).await;
        self.reserved_ports.clear();
    }
}
