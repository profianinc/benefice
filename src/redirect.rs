// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::ops::Range;

use axum::response::Redirect;

/// The server is already running too many jobs.
pub(crate) fn too_many_workloads() -> Redirect {
    Redirect::to("/?message=too_many_workloads")
}

/// A workload is trying to listen to too many ports at once.
pub(crate) fn too_many_listeners(listen_max: u16) -> Redirect {
    Redirect::to(&format!("/?message=too_many_listeners&max={listen_max}",))
}

/// Some listen ports are outside of the allowed range.
pub(crate) fn illegal_ports(illegal_ports: &[u16], port_range: Range<u16>) -> Redirect {
    Redirect::to(&format!(
        "/?message=illegal_ports&ports={}&range={}-{}",
        illegal_ports
            .iter()
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(","),
        port_range.start,
        port_range.end
    ))
}

/// Another workload already has some ports in use.
pub(crate) fn port_conflicts(port_conflicts: &[u16]) -> Redirect {
    Redirect::to(&format!(
        "/?message=port_conflicts&ports={}",
        port_conflicts
            .iter()
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(",")
    ))
}
