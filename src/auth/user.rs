// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Display;
use std::hash::Hash;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::time::SystemTime;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, NewAead, Nonce};
use axum::extract::{FromRequest, RequestParts};
use axum::headers::{Cookie, HeaderName};
use axum::http::HeaderValue;
use axum::http::{header::SET_COOKIE, StatusCode};
use axum::{async_trait, TypedHeader};
use base64::read::DecoderReader;
use base64::write::EncoderStringWriter;
use base64::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::Config;

const COOKIE_NAME: &str = "SESSION";

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub(crate) struct User {
    time: SystemTime,
    uid: u64,
    has_starred_enarx: bool,
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
    pub(super) fn create(
        config: &Config,
        uid: u64,
        has_starred_enarx: bool,
    ) -> (HeaderName, HeaderValue) {
        let time = SystemTime::now();
        let user = User {
            time,
            uid,
            has_starred_enarx,
        };

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

        (SET_COOKIE, HeaderValue::from_str(&s).unwrap())
    }

    pub(super) fn clear() -> (HeaderName, HeaderValue) {
        let s = format!("{}=; SameSite=Lax; Path=/; Max-Age=0", COOKIE_NAME);
        (SET_COOKIE, HeaderValue::from_str(&s).unwrap())
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
    pub(crate) fn has_starred_enarx(&self) -> bool {
        self.has_starred_enarx
    }
}
