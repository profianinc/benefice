// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use anyhow::Context;
use enarx_config::{Config, File};
use static_init::dynamic;
use tokio::sync::{RwLock, RwLockWriteGuard};

#[dynamic]
static PORTS_IN_USE: Arc<RwLock<Vec<u16>>> = Arc::new(RwLock::new(vec![]));

pub fn get_listen_ports(toml: &str) -> anyhow::Result<Vec<u16>> {
    let config = toml::from_str::<Config>(toml).with_context(|| "failed to parse enarx config")?;

    let ports = config
        .files
        .into_iter()
        .filter_map(|file| match file {
            File::Null { .. }
            | File::Stdin { .. }
            | File::Stdout { .. }
            | File::Stderr { .. }
            | File::Connect { .. } => None,
            File::Listen { port, .. } => Some(port),
        })
        .collect();

    Ok(ports)
}

pub async fn try_reserve(ports: &[u16]) -> Result<(), Vec<u16>> {
    let mut ports_in_use = PORTS_IN_USE.write().await;
    let conflicting = conflicting(ports, Some(&ports_in_use)).await;

    if !conflicting.is_empty() {
        return Err(conflicting);
    }

    ports_in_use.extend(ports);
    Ok(())
}

pub async fn free(ports: &[u16]) {
    let mut ports_in_use = PORTS_IN_USE.write().await;
    let to_remove = ports_in_use
        .iter()
        .enumerate()
        .filter_map(|(i, port)| match ports.contains(port) {
            true => Some(i),
            false => None,
        })
        .collect::<Vec<_>>();

    for index in to_remove {
        ports_in_use.remove(index);
    }
}

pub async fn conflicting<'a>(
    candidate_ports: &[u16],
    ports_in_use: Option<&RwLockWriteGuard<'a, Vec<u16>>>,
) -> Vec<u16> {
    let conflicting = |ports_in_use: &[u16]| -> Vec<u16> {
        candidate_ports
            .iter()
            .filter(|port| ports_in_use.contains(*port))
            .cloned()
            .collect::<Vec<_>>()
    };
    match ports_in_use {
        Some(ports_in_use) => conflicting(ports_in_use),
        None => conflicting(&PORTS_IN_USE.read().await),
    }
}
