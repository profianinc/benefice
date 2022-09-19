// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

mod key;
mod user;

pub(crate) use self::key::Key;
pub(crate) use self::user::User;
pub(crate) use openidconnect::url::Url;

use crate::last_page;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum::Router;
use axum_extra::extract::CookieJar;

use openidconnect::core::{CoreProviderMetadata, CoreResponseType, CoreUserInfoClaims};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthType, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl,
    Nonce, OAuth2TokenResponse, RedirectUrl,
};

use anyhow::{Context as _, Error};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Deserialize, Serialize, Debug)]
struct EnarxClaims {
    has_starred_enarx: Option<bool>,
}

impl openidconnect::AdditionalClaims for EnarxClaims {}

type OIDCClient = openidconnect::Client<
    EnarxClaims,
    openidconnect::core::CoreAuthDisplay,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJwsSigningAlgorithm,
    openidconnect::core::CoreJsonWebKeyType,
    openidconnect::core::CoreJsonWebKeyUse,
    openidconnect::core::CoreJsonWebKey,
    openidconnect::core::CoreAuthPrompt,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
    openidconnect::StandardTokenResponse<
        openidconnect::IdTokenFields<
            EnarxClaims,
            openidconnect::EmptyExtraTokenFields,
            openidconnect::core::CoreGenderClaim,
            openidconnect::core::CoreJweContentEncryptionAlgorithm,
            openidconnect::core::CoreJwsSigningAlgorithm,
            openidconnect::core::CoreJsonWebKeyType,
        >,
        openidconnect::core::CoreTokenType,
    >,
    openidconnect::core::CoreTokenType,
    openidconnect::core::CoreTokenIntrospectionResponse,
    openidconnect::core::CoreRevocableToken,
    openidconnect::core::CoreRevocationErrorResponse,
>;

struct Config {
    oidc: OIDCClient,
    ttl: Duration,
    key: Key,
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
}

fn ice<E: std::fmt::Debug>(info: &'static str) -> impl Fn(E) -> (StatusCode, &'static str) {
    move |e: E| {
        error!(info, error = ?e, "authentication error");
        (StatusCode::INTERNAL_SERVER_ERROR, info)
    }
}

fn accept_any_nonce(_: Option<&openidconnect::Nonce>) -> Result<(), String> {
    Ok(())
}

async fn authorized(
    Query(AuthRequest { code, .. }): Query<AuthRequest>,
    Extension(config): Extension<Arc<Config>>,
    jar: CookieJar,
) -> impl IntoResponse {
    // Get the OIDC token.
    let token = config
        .oidc
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await
        .map_err(ice("error constructing request token"))?;

    let has_starred_enarx = match token.extra_fields().id_token() {
        None => {
            error!("No id token found in response");
            false
        }
        Some(id_token) => {
            match id_token.claims(&config.oidc.id_token_verifier(), accept_any_nonce) {
                Err(e) => {
                    error!(error = ?e, "failed to verify claims");
                    false
                }
                Ok(claims) => match claims.additional_claims().has_starred_enarx {
                    None => {
                        error!("No has_starred_enarx claim found in id token");
                        false
                    }
                    Some(val) => val,
                },
            }
        }
    };

    // Get the OIDC claims from the User Info endpoint.
    let claims: CoreUserInfoClaims = config
        .oidc
        .user_info(token.access_token().clone(), None)
        .map_err(ice("error constructing user info request"))?
        .request_async(async_http_client)
        .await
        .map_err(ice("error fetching claims"))?;

    // Get the GitHub user identifier.
    match claims.subject().split_once('|') {
        Some(("github", uid)) => {
            let session_cookie = User::create(
                &config,
                uid.parse().map_err(ice("invalid uid"))?,
                has_starred_enarx,
            );
            let redirect_path = last_page(&jar).await.unwrap_or("/");
            Ok(([session_cookie], Redirect::to(redirect_path)).into_response())
        }
        _ => Err(ice("invalid user type")("unknown user type")),
    }
}

// TODO: invalidate the session on the remote server properly
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let session_cookie = User::clear();
    let redirect_path = last_page(&jar).await.unwrap_or("/");
    ([session_cookie], Redirect::to(redirect_path)).into_response()
}

async fn login(Extension(config): Extension<Arc<Config>>) -> impl IntoResponse {
    let request = config.oidc.authorize_url(
        AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );

    Redirect::temporary(request.url().0.as_str())
}

pub(crate) struct Oidc {
    pub(crate) server: Url,
    pub(crate) issuer: Url,
    pub(crate) client: String,
    pub(crate) secret: Option<String>,
    pub(crate) session_ttl: Duration,
    pub(crate) session_key: Key,
}

impl Oidc {
    pub(crate) async fn routes(self, router: Router) -> Result<Router, Error> {
        let redir = RedirectUrl::from_url(self.server.join("/authorized").unwrap());
        let secret = self.secret.map(ClientSecret::new);
        let url = IssuerUrl::from_url(self.issuer);
        let id = ClientId::new(self.client);

        let metadata = CoreProviderMetadata::discover_async(url, async_http_client)
            .await
            .with_context(|| "unable to fetch OIDC provider metadata")?;

        let oidc = OIDCClient::from_provider_metadata(metadata, id, secret)
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
