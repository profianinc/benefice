use std::process::Stdio;

use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

pub enum Standard {
    Output,
    Error,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Job {
    exec: Child,
    wasm: NamedTempFile,
    toml: NamedTempFile,
}

impl Job {
    pub fn new(cmd: String, wasm: NamedTempFile, toml: NamedTempFile) -> std::io::Result<Self> {
        let exec = Command::new(cmd)
            .arg("run")
            .arg("--wasmcfgfile")
            .arg(toml.path())
            .arg(wasm.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        Ok(Self { exec, wasm, toml })
    }

    pub async fn read(&mut self, kind: Standard, buffer: &mut [u8]) -> std::io::Result<usize> {
        match kind {
            Standard::Output => self.exec.stdout.as_mut().unwrap().read(buffer).await,
            Standard::Error => self.exec.stderr.as_mut().unwrap().read(buffer).await,
        }
    }
}
