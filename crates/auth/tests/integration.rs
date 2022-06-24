// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

mod protected;
mod providers;
mod status;

use benefice_auth::providers::github;
use benefice_auth::AuthRedirectRoot;

use axum::extract::Extension;
use axum::routing::get;
use axum::Router;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

pub const STATUS: &str = "/status";
pub const PROTECTED: &str = "/protected";

pub fn test_app(host: String) -> Router {
    // TODO: generate this key at runtime or pull the path from the command line args: https://github.com/profianinc/drawbridge/issues/18
    let key = RsaPrivateKey::from_pkcs8_der(include_bytes!("../rsa2048-priv.der")).unwrap();

    Router::new()
        .route(github::AUTHORIZED_URI, get(github::routes::authorized))
        .route(github::LOGIN_URI, get(github::routes::login))
        // TODO: add a test for the logout api and cookie storage
        .route(github::LOGOUT_URI, get(github::routes::logout))
        .route(STATUS, get(status::status))
        .route(PROTECTED, get(protected::protected))
        .layer(Extension(key))
        .layer(Extension(AuthRedirectRoot(host.clone())))
        .layer(Extension(github::OAuthClient::new(
            &host,
            std::env::var("CLIENT_ID").expect("github oauth CLIENT_ID"),
            std::env::var("CLIENT_SECRET").expect("github oauth CLIENT_SECRET"),
        )))
}
