// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, NewAead, Nonce};
use axum::extract::{FromRequest, RequestParts};
use axum::headers::Cookie;
use axum::http::HeaderValue;
use axum::http::{header::SET_COOKIE, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{async_trait, TypedHeader};
use base64::read::DecoderReader;
use base64::write::EncoderStringWriter;
use base64::URL_SAFE_NO_PAD;
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::error;

use crate::HTTP;

use super::Config;

const STAR_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const COOKIE_NAME: &str = "SESSION";

static STAR: Lazy<RwLock<HashMap<(u64, &'static str), bool>>> = Lazy::new(|| HashMap::new().into());

#[derive(Debug, Deserialize)]
struct Repo {
    full_name: String,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub(crate) struct User {
    time: SystemTime,
    uid: u64,
}

impl Eq for User {}

impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.uid == other.uid
    }
}

impl Hash for User {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.uid.hash(state);
    }
}

impl Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.uid.fmt(f)
    }
}

impl User {
    pub(super) fn create(config: &Config, uid: u64) -> Response {
        let time = SystemTime::now();
        let user = User { time, uid };

        // Encode the structure.
        let plaintext = serde_json::to_vec(&user).unwrap();

        // Generate the nonce.
        let mut rng = rand::thread_rng();
        let mut nonce = Nonce::default();
        rng.fill_bytes(&mut nonce);

        // Do the encryption.
        let aes = Aes128Gcm::new(&config.key);
        let ciphertext = aes.encrypt(&nonce, &*plaintext).unwrap();

        // Encode the results.
        let mut b64 = EncoderStringWriter::new(URL_SAFE_NO_PAD);
        b64.write_all(&nonce).unwrap();
        b64.write_all(&ciphertext).unwrap();

        // Create the cookie.
        let s = format!(
            "{}={}; SameSite=Lax; Path=/; Max-Age={}",
            COOKIE_NAME,
            b64.into_inner(),
            config.ttl.as_secs(),
        );

        let header = (SET_COOKIE, HeaderValue::from_str(&s).unwrap());
        ([header], Redirect::to("/")).into_response()
    }

    pub(super) fn clear() -> Response {
        let s = format!("{}=; SameSite=Lax; Path=/; Max-Age=0", COOKIE_NAME);
        let header = (SET_COOKIE, HeaderValue::from_str(&s).unwrap());
        ([header], Redirect::to("/")).into_response()
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for User {
    type Rejection = StatusCode;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // Get the configuration.
        let config = req.extensions().get::<Arc<Config>>().cloned().unwrap();

        // Get the session cookie.
        let cookies = TypedHeader::<Cookie>::from_request(req)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let value = cookies.get(COOKIE_NAME).ok_or(StatusCode::BAD_REQUEST)?;

        // Decode the input.
        let mut cur = Cursor::new(value.as_bytes());
        let mut b64 = DecoderReader::new(&mut cur, URL_SAFE_NO_PAD);

        // Read the nonce.
        let mut nonce = Nonce::default();
        b64.read_exact(&mut nonce)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        // Read the ciphertext.
        let mut ciphertext = Vec::new();
        let _ = b64
            .read_to_end(&mut ciphertext)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        // Decrypt the ciphertext.
        let aes = Aes128Gcm::new(&config.key);
        let plaintext = aes
            .decrypt(&nonce, &*ciphertext)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        // Decode the object.
        let user: User = serde_json::from_slice(&plaintext).map_err(|_| StatusCode::BAD_REQUEST)?;

        // Check for freshness.
        if user.time + config.ttl < SystemTime::now() {
            return Err(StatusCode::BAD_REQUEST);
        }

        Ok(user)
    }
}

impl User {
    pub(crate) async fn is_starred(&self, repo: &'static str) -> bool {
        if let Some(star) = STAR.read().await.get(&(self.uid, repo)) {
            return *star;
        }

        let result = HTTP
            .get(&format!("https://api.github.com/user/{}/starred", self.uid))
            .send();

        match result.await {
            Err(e) => {
                error!("error fetching github star status: {}", e);
                false
            }

            Ok(response) => match response.json::<Vec<Repo>>().await {
                Ok(repos) => {
                    let star = repos.iter().any(|r| r.full_name == repo);

                    let uid = self.uid;
                    _ = STAR.write().await.insert((uid, repo), star);
                    _ = tokio::spawn(async move {
                        sleep(STAR_TIMEOUT).await;
                        _ = STAR.write().await.remove(&(uid, repo));
                    });

                    star
                }

                Err(e) => {
                    error!("error parsing github star status: {}", e);
                    false
                }
            },
        }
    }
}
