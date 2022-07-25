// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use axum::async_trait;
use axum::extract::{FromRequest, RequestParts};
use axum::response::Response;
use once_cell::sync::Lazy;
use reqwest::{Client, ClientBuilder};
use serde::Deserialize;
use tracing::error;

use crate::reference::Ref;

use super::Session;

static HTTP: Lazy<Client> = Lazy::new(|| {
    const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
    ClientBuilder::new().user_agent(USER_AGENT).build().unwrap()
});

#[derive(Debug, Deserialize)]
struct Repo {
    pub full_name: String,
}

#[derive(Debug)]
pub struct User<T> {
    pub uid: usize,
    pub data: T,
}

#[async_trait]
impl<T: 'static + Send + Sync, B: Send> FromRequest<B> for Ref<User<T>> {
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let session = Ref::<Session<T>>::from_request(req).await?;
        let user = session.read().await.user.clone();
        Ok(user)
    }
}

impl<T> User<T> {
    pub async fn is_starred(&self, repo: &str) -> bool {
        let result = HTTP
            .get(&format!("https://api.github.com/user/{}/starred", self.uid))
            .send();

        match result.await {
            Err(e) => {
                error!("error fetching github star status: {}", e);
                false
            }

            Ok(response) => match response.json::<Vec<Repo>>().await {
                Ok(repos) => repos.iter().any(|r| r.full_name == repo),

                Err(e) => {
                    error!("error parsing github star status: {}", e);
                    false
                }
            },
        }
    }
}
