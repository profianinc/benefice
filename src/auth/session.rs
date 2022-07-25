// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::hash::Hash;

use crate::reference::Ref;

use super::{SessionId, User};

#[derive(Debug)]
pub struct Session<T> {
    pub sid: SessionId,
    pub user: Ref<User<T>>,
}

impl<T> PartialEq for Session<T>
where
    Ref<User<T>>: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.sid == other.sid && self.user == other.user
    }
}

impl<T> Eq for Session<T> where Ref<User<T>>: Eq {}

impl<T> Hash for Session<T>
where
    Ref<User<T>>: Hash,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.sid.hash(state);
        self.user.hash(state);
    }
}
