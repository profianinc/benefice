// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use axum::response::Redirect;

/// The user has no session and has likely been logged out.
pub fn no_session() -> Redirect {
    Redirect::to("/?message=no_session")
}

/// A user has insufficient permissions or a workload does not exist.
pub fn workload_not_found() -> Redirect {
    Redirect::to("/?message=workload_not_found")
}

/// The server is already running too many jobs.
pub fn too_many_workloads() -> Redirect {
    Redirect::to("/?message=too_many_workloads")
}

/// A user already has a running workload.
pub fn workload_running() -> Redirect {
    Redirect::to("/?message=workload_running")
}

/// An internal error occurred.
pub fn internal_error() -> Redirect {
    Redirect::to("/?message=internal_error")
}
