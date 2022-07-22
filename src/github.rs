// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Context;
use serde::Deserialize;

static USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Deserialize)]
struct Repo {
    pub full_name: String,
}

pub async fn has_starred(github_id: &str, repo_full_name: &str) -> anyhow::Result<bool> {
    Ok(reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .build()?
        .get(&format!("https://api.github.com/user/{github_id}/starred"))
        .send()
        .await
        .with_context(|| "Failed to get body from /starred request")?
        .json::<Vec<Repo>>()
        .await
        .with_context(|| "Failed to parse body from /starred request")?
        .iter()
        .any(|repo| repo.full_name == *repo_full_name))
}
