// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use axum::extract::{FromRequest, RequestParts};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{async_trait, Extension};

use openidconnect::core::{CoreClient, CoreResponseType, CoreUserInfoClaims};
use openidconnect::reqwest::async_http_client;
use openidconnect::url::Url;
use openidconnect::{AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse};

use anyhow::Result;
use tracing::error;

use super::{Ref, Sessions};

#[derive(Debug)]
pub struct Context<T> {
    sessions: Ref<Sessions<T>>,
    oidc: CoreClient,
}

impl<T> Context<T> {
    pub fn new(ttl: Duration, oidc: CoreClient) -> Self {
        Self {
            sessions: Ref::from(Sessions::from(ttl)),
            oidc,
        }
    }

    pub fn start_auth(&self) -> Url {
        self.oidc
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .url()
            .0
    }

    pub fn sessions(&self) -> Ref<Sessions<T>> {
        self.sessions.clone()
    }
}

impl<T: 'static + Send + Sync + Default> Ref<Context<T>> {
    pub async fn fetch_claims(self, code: String) -> Result<CoreUserInfoClaims> {
        // Get the OIDC token.
        let token = self
            .read()
            .await
            .oidc
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await?;

        // Get the OIDC claims from the token.
        let claims = self
            .read()
            .await
            .oidc
            .user_info(token.access_token().clone(), None)?
            .request_async(async_http_client)
            .await?;

        Ok(claims)
    }
}

#[async_trait]
impl<T: 'static + Send + Sync, B: Send> FromRequest<B> for Ref<Context<T>> {
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        Ok(Extension::<Self>::from_request(req)
            .await
            .map_err(|e| {
                error!("error fetching context: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?
            .0)
    }
}
