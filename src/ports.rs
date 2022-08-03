// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::{collections::HashSet, sync::Arc};

use anyhow::Context;
use enarx_config::{Config, File, Protocol};
use lazy_static::lazy_static;
use tokio::sync::{RwLock, RwLockWriteGuard};

lazy_static! {
    static ref PORTS_IN_USE: Arc<RwLock<HashSet<u16>>> = Arc::new(RwLock::new(HashSet::new()));
}

pub fn get_listen_ports(toml: &str) -> anyhow::Result<Vec<(u16, Protocol)>> {
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
            File::Listen { port, prot, .. } => match prot {
                Protocol::Tls | Protocol::Tcp => Some((port, prot)),
            },
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

    for port in ports {
        ports_in_use.remove(port);
    }
}

pub async fn conflicting<'a>(
    candidate_ports: &[u16],
    ports_in_use: Option<&RwLockWriteGuard<'a, HashSet<u16>>>,
) -> Vec<u16> {
    let conflicting = |ports_in_use: &HashSet<u16>| -> Vec<u16> {
        candidate_ports
            .iter()
            .filter(|port| ports_in_use.contains(*port))
            .cloned()
            .collect::<Vec<_>>()
    };
    match ports_in_use {
        Some(ports_in_use) => conflicting(ports_in_use),
        None => conflicting(&*PORTS_IN_USE.read().await),
    }
}
