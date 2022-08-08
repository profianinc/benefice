// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::hash::Hash;
use std::ops::Deref;
use std::sync::{Arc, Weak};

use tokio::sync::RwLock;

#[derive(Debug)]
pub(crate) struct Ref<T>(Arc<RwLock<T>>);

impl<T> Ref<T> {
    pub(crate) fn downgrade(this: &Ref<T>) -> Weak<RwLock<T>> {
        Arc::downgrade(&this.0)
    }
}

impl<T> Eq for Ref<T> {}
impl<T> PartialEq for Ref<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::as_ptr(&self.0) == Arc::as_ptr(&other.0)
    }
}

impl<T> Hash for Ref<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state)
    }
}

impl<T> Clone for Ref<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Deref for Ref<T> {
    type Target = RwLock<T>;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<T> From<Arc<RwLock<T>>> for Ref<T> {
    fn from(value: Arc<RwLock<T>>) -> Self {
        Self(value)
    }
}

impl<T> From<RwLock<T>> for Ref<T> {
    fn from(value: RwLock<T>) -> Self {
        Self(value.into())
    }
}

impl<T> From<T> for Ref<T> {
    fn from(value: T) -> Self {
        Self(RwLock::from(value).into())
    }
}
