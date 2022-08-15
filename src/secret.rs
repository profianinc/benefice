// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use anyhow::{anyhow, Context, Error};
use zeroize::Zeroizing;

use crate::auth::Key;

#[derive(Debug)]
pub struct SecretFile<T>(T);

impl From<SecretFile<Key>> for Key {
    fn from(sf: SecretFile<Key>) -> Self {
        sf.0
    }
}

impl From<SecretFile<String>> for String {
    fn from(sf: SecretFile<String>) -> Self {
        sf.0
    }
}

impl FromStr for SecretFile<Key> {
    type Err = Error;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let data = Zeroizing::new(
            std::fs::read(path)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("error reading secret at `{path}`"))?,
        );

        let mut key = Key::default();
        if data.len() != key.as_slice().len() {
            return Err(anyhow!(
                "secret at `{path}` MUST have size {}",
                key.as_slice().len()
            ));
        }

        key.as_mut_slice().copy_from_slice(&data);
        Ok(Self(key))
    }
}

impl FromStr for SecretFile<String> {
    type Err = Error;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut data = std::fs::read_to_string(path)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("error reading secret at `{path}`"))?;

        data.truncate(data.trim_end().len());
        Ok(Self(data))
    }
}
