// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use axum::response::Redirect;

/// The server is already running too many jobs.
pub fn too_many_workloads() -> Redirect {
    Redirect::to("/?message=too_many_workloads")
}
