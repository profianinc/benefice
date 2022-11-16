// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use aes_gcm::{Aes128Gcm, NewAead};
use rand::RngCore;
use zeroize::Zeroize;

type KeySize = <Aes128Gcm as NewAead>::KeySize;

#[derive(Clone)]
pub struct Key(aes_gcm::Key<KeySize>);

impl Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Key").finish()
    }
}

impl Default for Key {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let mut key = aes_gcm::Key::<KeySize>::default();
        rng.fill_bytes(key.as_mut_slice());
        Self(key)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize()
    }
}

impl Deref for Key {
    type Target = aes_gcm::Key<KeySize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Key {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
