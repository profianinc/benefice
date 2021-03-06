// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::ops::Deref;

use crate::redirect;

use axum::extract::{Extension, FromRequest, Query, RequestParts};
use axum::headers;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{async_trait, TypedHeader};
use openidconnect::core::{CoreClient, CoreResponseType, CoreUserInfoClaims};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AccessToken, AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse,
};
use serde::Deserialize;
use tracing::{debug, error, trace};

const COOKIE_NAME: &str = "SESSION";

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub code: String,
    pub state: String,
}

pub enum ClaimsError {
    // TODO: handle refresh tokens here: https://github.com/profianinc/benefice/issues/43
    // ExpiredToken(String),
    InvalidSession(String),
    NoToken(String),
    InternalError(String),
}

impl ClaimsError {
    pub fn redirect_response(self) -> Redirect {
        match self {
            ClaimsError::InvalidSession(_) | ClaimsError::NoToken(_) => redirect::no_session(),
            ClaimsError::InternalError(_) => redirect::internal_error(),
        }
    }
}

impl IntoResponse for ClaimsError {
    fn into_response(self) -> Response {
        match self {
            ClaimsError::InvalidSession(message) | ClaimsError::NoToken(message) => {
                (StatusCode::UNAUTHORIZED, message).into_response()
            }
            ClaimsError::InternalError(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
    }
}

/// Allow users to authenticate using credentials cached in their last job.
/// This is much faster and avoids rate limiting.
#[derive(Clone, Debug)]
pub struct WorkloadSession {
    pub user: String,
}

#[async_trait]
impl<B: Send> FromRequest<B> for WorkloadSession {
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let cookies = TypedHeader::<headers::Cookie>::from_request(req)
            .await
            .map_err(|e| {
                debug!("failed to retrieve cookies from request: {e}");
                StatusCode::UNAUTHORIZED.into_response()
            })?;

        let token = cookies
            .get(COOKIE_NAME)
            .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

        let lock = crate::OUT.read().await;

        for state in lock.values() {
            let lock = state.lock().await;

            if lock.token.secret() == token {
                return Ok(Self {
                    user: lock.user.clone(),
                });
            }
        }

        Err(StatusCode::UNAUTHORIZED.into_response())
    }
}

#[derive(Clone, Debug)]
pub struct Claims(CoreUserInfoClaims, AccessToken);

impl Claims {
    /// The GitHub user for the claims.
    ///
    /// If not a GitHub account, returns `None`.
    pub fn github(&self) -> Option<&str> {
        match self.subject().split_once('|') {
            Some(("github", user)) => Some(user),
            _ => None,
        }
    }

    pub fn token(&self) -> &AccessToken {
        &self.1
    }
}

impl Deref for Claims {
    type Target = CoreUserInfoClaims;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for Claims {
    type Rejection = ClaimsError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let cookies = TypedHeader::<headers::Cookie>::from_request(req)
            .await
            .map_err(|e| {
                debug!("failed to retrieve cookies from request: {e}");
                ClaimsError::NoToken("Authorization failed".to_string())
            })?;

        let token = cookies
            .get(COOKIE_NAME)
            .ok_or_else(|| ClaimsError::NoToken("Authorization failed".to_string()))?;

        let Extension(oidc) = req.extract::<Extension<CoreClient>>().await.map_err(|e| {
            error!("OpenID Connect client extension missing: {e}");
            ClaimsError::InternalError("OpenID Connect client extension missing".to_string())
        })?;

        let token = AccessToken::new(token.into());
        let info_req = oidc.user_info(token.clone(), None).map_err(|e| {
            error!("failed to construct user info request: {e}");
            ClaimsError::InternalError("OpenID Connect client initialization failed".to_string())
        })?;

        trace!("request user info");
        let claims = info_req
            .request_async(async_http_client)
            .await
            .map_err(|e| {
                debug!("failed to request user info: {e}");
                ClaimsError::InvalidSession(format!(
                    "OpenID Connect credential validation failed: {e}"
                ))
            })?;
        trace!("received user claims: {:?}", claims);
        Ok(Self(claims, token))
    }
}

pub async fn login(Extension(client): Extension<CoreClient>) -> impl IntoResponse {
    let (authorize_url, _csrf_state, _nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .url();

    Redirect::temporary(authorize_url.as_str())
}

// TODO: invalidate the session on the remote server properly
pub async fn logout() -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let cookie = format!("{COOKIE_NAME}=; Path=/; Max-Age=0");
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        cookie.parse().map_err(|e| {
            error!("failed prepare set cookie header: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error preparing headers".to_string(),
            )
        })?,
    );
    Ok((headers, Redirect::to("/")))
}

pub async fn authorized(
    query: Query<AuthRequest>,
    Extension(client): Extension<CoreClient>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let token_response = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            error!("failed to exchange code for auth token: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve auth token".to_string(),
            )
        })?;

    let access_token = token_response.access_token();
    let cookie = format!(
        "{}={}; SameSite=Lax; Path=/",
        COOKIE_NAME,
        access_token.secret()
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        cookie.parse().map_err(|e| {
            error!("failed prepare set cookie header: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error preparing headers".to_string(),
            )
        })?,
    );
    Ok((headers, Redirect::to("/")))
}
