// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{bail, Context};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Repo {
    pub full_name: String,
}

pub fn has_starred(github_id: &str, repo_full_name: &str) -> anyhow::Result<bool> {
    let response = ureq::get(&format!("https://api.github.com/user/{github_id}/starred")).call()?;

    if response.status() != 200 {
        bail!("Failed to get starred repos for user {github_id}");
    }

    let body = response
        .into_string()
        .with_context(|| "Failed to get body from /starred request")?;
    let repos = serde_json::from_str::<Vec<Repo>>(&body)
        .with_context(|| "Failed to parse body from /starred request")?;

    Ok(repos.iter().any(|repo| repo.full_name == *repo_full_name))
}
