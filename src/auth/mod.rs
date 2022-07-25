// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

mod context;
mod session;
mod sessions;
mod sid;
mod user;

pub use self::user::User;
pub use openidconnect::url::Url;

use std::fmt::Display;
use std::time::Duration;

use axum::extract::{Extension, Query};
use axum::headers::HeaderName;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum::Router;

use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{AuthType, ClientId, ClientSecret, IssuerUrl, RedirectUrl};

use anyhow::{Context as _, Error};
use serde::Deserialize;
use tracing::error;

use self::context::Context;
use self::session::Session;
use self::sessions::Sessions;
use self::sid::SessionId;
use crate::reference::Ref;

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
}

async fn authorized<T: 'static + Send + Sync + Default>(
    Query(AuthRequest { code, .. }): Query<AuthRequest>,
    Extension(ctx): Extension<Ref<Context<T>>>,
) -> Result<([(HeaderName, HeaderValue); 1], Redirect), (StatusCode, &'static str)> {
    fn ice<E: Display>(info: &'static str) -> impl Fn(E) -> (StatusCode, &'static str) {
        move |e: E| {
            error!("{}: {}", info, e);
            (StatusCode::INTERNAL_SERVER_ERROR, info)
        }
    }

    // Get the OIDC claims.
    let claims = ctx
        .clone()
        .fetch_claims(code)
        .await
        .map_err(ice("error fetching claims"))?;

    // Get the GitHub user identifier.
    let uid: usize = match claims.subject().split_once('|') {
        Some(("github", uid)) => uid.parse().map_err(ice("invalid uid"))?,
        _ => return Err(ice("invalid user type")("unknown user type")),
    };

    // Return the cookie.
    let cookie = ctx.read().await.sessions().create_session(uid).await;
    Ok(([cookie], Redirect::to("/")))
}

// TODO: invalidate the session on the remote server properly
async fn logout(sid: SessionId) -> ([(HeaderName, HeaderValue); 1], Redirect) {
    ([sid.clear()], Redirect::to("/"))
}

async fn login<T: 'static + Send + Sync>(
    Extension(ctx): Extension<Ref<Context<T>>>,
) -> impl IntoResponse {
    Redirect::temporary(ctx.read().await.start_auth().as_str())
}

pub struct Oidc {
    pub server: Url,
    pub issuer: Url,
    pub client: String,
    pub secret: Option<String>,
    pub ttl: Duration,
}

impl Oidc {
    pub async fn routes<T: 'static + Send + Sync + Default>(
        self,
        router: Router,
    ) -> Result<Router, Error> {
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

        let ctx = Ref::from(Context::<T>::new(self.ttl, oidc));

        Ok(router
            .route("/authorized", get(authorized::<T>))
            .route("/logout", get(logout))
            .route("/login", get(login::<T>))
            .layer(Extension(ctx)))
    }
}
