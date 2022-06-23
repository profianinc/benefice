// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::Provider;
use super::OAuthClient;
use crate::session::Session;
use crate::COOKIE_NAME;

use axum::extract::{Extension, Query};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use oauth2::ureq::http_client;
use oauth2::{AuthorizationCode, CsrfToken, Scope, TokenResponse};
use rsa::RsaPrivateKey;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub code: String,
    pub state: String,
}

/// Authenticate with GitHub OAuth.
pub async fn login(Extension(OAuthClient(client)): Extension<OAuthClient>) -> impl IntoResponse {
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .url();

    Redirect::to(auth_url.as_str())
}

/// Logout the user by deleting their session cookie.
/// Anyone who still has access to that session cookie will still be logged in.
pub async fn logout() -> impl IntoResponse {
    let cookie = format!("{COOKIE_NAME}=; Path=/; Max-Age=0");
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());
    (headers, Redirect::to("/"))
}

/// Prepare an encrypted token for GitHub OAuth. 
pub async fn authorized(
    query: Query<AuthRequest>,
    Extension(OAuthClient(client)): Extension<OAuthClient>,
    Extension(key): Extension<RsaPrivateKey>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let token = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request(http_client)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get token: {}", e),
            )
        })?;

    let token = Session::new(Provider::GitHub, token.access_token().clone())
        .encrypt(&key)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encrypt token: {}", e),
            )
        })?;

    let cookie = format!("{}={}; SameSite=Lax; Path=/", COOKIE_NAME, token);
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    Ok((headers, Redirect::to("/")))
}
