use std::process::Stdio;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use uuid::Uuid;

static COUNT: AtomicUsize = AtomicUsize::new(0);

pub enum Standard {
    Output,
    Error,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Job {
    pub uuid: Uuid,
    exec: Child,
    wasm: NamedTempFile,
    toml: NamedTempFile,
}

impl Drop for Job {
    fn drop(&mut self) {
        COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Job {
    pub fn count() -> usize {
        COUNT.load(Ordering::SeqCst)
    }

    pub fn new(cmd: String, wasm: NamedTempFile, toml: NamedTempFile) -> std::io::Result<Self> {
        let uuid = Uuid::new_v4();
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

        COUNT.fetch_add(1, Ordering::SeqCst);

        Ok(Self {
            uuid,
            exec,
            wasm,
            toml,
        })
    }

    pub async fn read(&mut self, kind: Standard, buffer: &mut [u8]) -> std::io::Result<usize> {
        match kind {
            Standard::Output => self.exec.stdout.as_mut().unwrap().read(buffer).await,
            Standard::Error => self.exec.stderr.as_mut().unwrap().read(buffer).await,
        }
    }
}
