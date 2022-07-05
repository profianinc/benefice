use std::ops::Deref;

use axum::extract::{Extension, FromRequest, Query, RequestParts};
use axum::headers;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{async_trait, TypedHeader};
use openidconnect::core::{CoreClient, CoreResponseType, CoreUserInfoClaims};
use openidconnect::ureq::http_client;
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

#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct Claims(CoreUserInfoClaims);

impl Deref for Claims {
    type Target = CoreUserInfoClaims;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for Claims {
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let cookies = TypedHeader::<headers::Cookie>::from_request(req)
            .await
            .map_err(|e| {
                debug!("failed to retrieve cookies from request: {e}");
                (
                    StatusCode::UNAUTHORIZED,
                    "Failed to get cookies from request",
                )
                    .into_response()
            })?;

        let token = cookies.get(COOKIE_NAME).ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Authorization failed".to_string()).into_response()
        })?;

        let Extension(oidc) = req.extract::<Extension<CoreClient>>().await.map_err(|e| {
            error!("OpenID Connect client extension missing: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "OpenID Connect client extension missing".to_string(),
            )
                .into_response()
        })?;

        let token = AccessToken::new(token.into());
        let info_req = oidc.user_info(token, None).map_err(|e| {
            error!("failed to construct user info request: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "OpenID Connect client initialization failed",
            )
                .into_response()
        })?;

        trace!("request user info");
        let claims = info_req.request(http_client).map_err(|e| {
            debug!("failed to request user info: {e}");
            (
                StatusCode::UNAUTHORIZED,
                format!("OpenID Connect credential validation failed: {e}"),
            )
                .into_response()
        })?;
        trace!("received user claims: {:?}", claims);
        Ok(Self(claims))
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
        .request(http_client)
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
