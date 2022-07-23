// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use anyhow::{Context, Error};

#[derive(Debug)]
pub struct SecretFile(String);

impl From<SecretFile> for String {
    fn from(sf: SecretFile) -> Self {
        sf.0
    }
}

impl FromStr for SecretFile {
    type Err = Error;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut data = std::fs::read_to_string(path)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("error reading secret at `{path}`"))?;

        data.truncate(data.trim_end().len());
        Ok(Self(data))
    }
}
