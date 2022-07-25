// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::time::Duration;

use axum::async_trait;
use axum::extract::{FromRequest, RequestParts};
use axum::headers::HeaderName;
use axum::http::{HeaderValue, StatusCode};

use axum::response::{IntoResponse, Response};
use tokio::time::sleep;

use super::{Context, Session, SessionId, User};
use crate::reference::Ref;

#[derive(Debug)]
pub struct Sessions<T> {
    map: HashMap<SessionId, Ref<Session<T>>>,
    ttl: Duration,
}

impl<T> From<Duration> for Sessions<T> {
    fn from(ttl: Duration) -> Self {
        let map = HashMap::default();
        Self { map, ttl }
    }
}

impl<T: Default> Sessions<T> {
    async fn make_session(&mut self, uid: usize) -> SessionId {
        let sid = SessionId::new();

        // Check to see if the user is already logged in.
        for (.., v) in self.map.iter() {
            let user = v.read().await.user.clone();
            if user.read().await.uid == uid {
                self.map.insert(sid, Session { sid, user }.into());
                return sid;
            }
        }

        // Create the user.
        let user = User {
            uid,
            data: T::default(),
        };

        // Create the session.
        let session = Session {
            sid,
            user: user.into(),
        };

        // Insert the session.
        self.map.insert(sid, session.into());
        sid
    }
}

impl<T: 'static + Send + Sync + Default> Ref<Sessions<T>> {
    pub async fn create_session(self, uid: usize) -> (HeaderName, HeaderValue) {
        // Create the session.
        let sid = self.write().await.make_session(uid).await;
        let ttl = self.read().await.ttl;

        // Destroy the session after the timeout.
        let weak = Ref::downgrade(&self);
        tokio::spawn(async move {
            sleep(ttl).await;
            if let Some(arc) = weak.upgrade() {
                arc.write().await.map.remove(&sid);
            }
        });

        // Return the header.
        sid.until(ttl)
    }
}

#[async_trait]
impl<T: 'static + Send + Sync, B: Send> FromRequest<B> for Ref<Sessions<T>> {
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let ctx = Ref::<Context<T>>::from_request(req).await?;
        let lck = ctx.read().await;
        Ok(lck.sessions())
    }
}

#[async_trait]
impl<T: 'static + Send + Sync, B: Send> FromRequest<B> for Ref<Session<T>> {
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let sid = SessionId::from_request(req).await?;
        let all = Ref::<Sessions<T>>::from_request(req).await?;
        let lck = all.read().await;

        Ok(lck
            .map
            .get(&sid)
            .cloned()
            .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?)
    }
}
