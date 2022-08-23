// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    ops::Range,
    sync::Arc,
};

use anyhow::Context;
use enarx_config::{Config, File, Protocol};
use once_cell::sync::Lazy;
use rand::prelude::*;
use tokio::sync::RwLock;

static PORTS_IN_USE: Lazy<Arc<RwLock<HashSet<u16>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashSet::new())));

fn random_unused_port(ports_in_use: &HashSet<u16>, range: Range<u16>) -> Option<u16> {
    for _ in 0..1000 {
        let port = rand::thread_rng().gen_range(range.clone());

        if !ports_in_use.contains(&port) {
            return Some(port);
        }
    }

    None
}

pub(crate) fn get_listen_ports(toml: &str) -> anyhow::Result<Vec<u16>> {
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
                Protocol::Tls | Protocol::Tcp => Some(port),
            },
        })
        .collect();

    Ok(ports)
}

pub(crate) async fn try_reserve(
    ports: Vec<u16>,
    port_range: &Option<Range<u16>>,
) -> Result<HashMap<u16, u16>, ()> {
    let mut result = HashMap::new();
    let mut ports_in_use = PORTS_IN_USE.write().await;
    let port_range = port_range.as_ref().unwrap_or(&(0..u16::MAX));

    for port in ports.into_iter() {
        let unused_port = random_unused_port(&ports_in_use, port_range.clone()).ok_or(())?;
        let _ = result.insert(port, unused_port);
        let _ = ports_in_use.insert(unused_port);
    }

    Ok(result)
}

pub(crate) async fn free(ports: &HashMap<u16, u16>) {
    let mut ports_in_use = PORTS_IN_USE.write().await;

    for port in ports.values() {
        _ = ports_in_use.remove(port);
    }
}
