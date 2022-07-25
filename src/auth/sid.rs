// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use axum::extract::{FromRequest, RequestParts};
use axum::headers::{Cookie, HeaderName, HeaderValue};
use axum::http::header::SET_COOKIE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{async_trait, TypedHeader};

use uuid::Uuid;

const COOKIE_NAME: &str = "SESSION";

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn until(&self, duration: Duration) -> (HeaderName, HeaderValue) {
        let s = format!(
            "{}={}; SameSite=Lax; Path=/; Max-Age={}",
            COOKIE_NAME,
            self.0,
            duration.as_secs()
        );

        (SET_COOKIE, s.parse().unwrap())
    }

    pub fn clear(&self) -> (HeaderName, HeaderValue) {
        let s = format!("{}=; SameSite=Lax; Path=/; Max-Age=0", COOKIE_NAME);

        (SET_COOKIE, s.parse().unwrap())
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for SessionId {
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let cookies = TypedHeader::<Cookie>::from_request(req)
            .await
            .map_err(|e| e.into_response())?;

        let value = cookies
            .get(COOKIE_NAME)
            .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;

        let uuid = value
            .parse()
            .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;

        Ok(Self(uuid))
    }
}
