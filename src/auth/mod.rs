// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

mod key;
mod user;

use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum::Router;

use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType, CoreUserInfoClaims};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthType, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl,
    Nonce, OAuth2TokenResponse, RedirectUrl,
};

use anyhow::{Context as _, Error};
use serde::Deserialize;
use tracing::error;

pub use self::key::Key;
pub use self::user::User;
pub use openidconnect::url::Url;

struct Config {
    oidc: CoreClient,
    ttl: Duration,
    key: Key,
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
}

fn ice<E: Display>(info: &'static str) -> impl Fn(E) -> (StatusCode, &'static str) {
    move |e: E| {
        error!("{}: {}", info, e);
        (StatusCode::INTERNAL_SERVER_ERROR, info)
    }
}

async fn authorized(
    Query(AuthRequest { code, .. }): Query<AuthRequest>,
    Extension(config): Extension<Arc<Config>>,
) -> impl IntoResponse {
    // Get the OIDC token.
    let token = config
        .oidc
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await
        .map_err(ice("error constructing request token"))?;

    // Get the OIDC claims from the token.
    let claims: CoreUserInfoClaims = config
        .oidc
        .user_info(token.access_token().clone(), None)
        .map_err(ice("error constructing user info request"))?
        .request_async(async_http_client)
        .await
        .map_err(ice("error fetching claims"))?;

    // Get the GitHub user identifier.
    match claims.subject().split_once('|') {
        Some(("github", uid)) => Ok(User::create(
            &config,
            uid.parse().map_err(ice("invalid uid"))?,
        )),

        _ => Err(ice("invalid user type")("unknown user type")),
    }
}

// TODO: invalidate the session on the remote server properly
async fn logout() -> impl IntoResponse {
    User::clear()
}

async fn login(Extension(config): Extension<Arc<Config>>) -> impl IntoResponse {
    let request = config.oidc.authorize_url(
        AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );

    Redirect::temporary(request.url().0.as_str())
}

pub struct Oidc {
    pub server: Url,
    pub issuer: Url,
    pub client: String,
    pub secret: Option<String>,
    pub session_ttl: Duration,
    pub session_key: Key,
}

impl Oidc {
    pub async fn routes(self, router: Router) -> Result<Router, Error> {
        let redir = RedirectUrl::from_url(self.server.join("/authorized").unwrap());
        let secret = self.secret.map(ClientSecret::new);
        let url = IssuerUrl::from_url(self.issuer);
        let id = ClientId::new(self.client);

        let metadata = CoreProviderMetadata::discover_async(url, async_http_client)
            .await
            .with_context(|| "unable to fetch OIDC provider metadata")?;

        let oidc = CoreClient::from_provider_metadata(metadata, id, secret)
            .set_redirect_uri(redir)
            .set_auth_type(AuthType::RequestBody);

        Ok(router
            .route("/authorized", get(authorized))
            .route("/logout", get(logout))
            .route("/login", get(login))
            .layer(Extension(Arc::new(Config {
                oidc,
                key: self.session_key,
                ttl: self.session_ttl,
            }))))
    }
}
