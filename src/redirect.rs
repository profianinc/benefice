// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use axum::response::Redirect;

/// Redirect the user to the home page with no warnings or errors.
pub fn home() -> Redirect {
    Redirect::to("/")
}

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

/// The user has successfully terminated a workload.
pub fn workload_killed() -> Redirect {
    Redirect::to("/?message=workload_killed")
}

/// An internal error occurred.
pub fn internal_error() -> Redirect {
    Redirect::to("/?message=internal_error")
}
