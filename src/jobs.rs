// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use uuid::Uuid;

use super::auth::User;
use super::job::Job;

#[derive(Default)]
pub(crate) struct Jobs {
    user_to_job_uuid: HashMap<User, Uuid>,
    uuid_to_job: HashMap<Uuid, Arc<RwLock<Job>>>,
}

impl Jobs {
    pub(crate) fn count(&self) -> usize {
        self.uuid_to_job.len()
    }

    pub(crate) fn insert(&mut self, user: User, job: Job) {
        _ = self.user_to_job_uuid.insert(user, job.uuid);
        _ = self.uuid_to_job.insert(job.uuid, RwLock::new(job).into());
    }

    pub(crate) async fn remove(&mut self, user: &User) -> Option<Uuid> {
        let uuid = self.kill(user).await?;
        _ = self.user_to_job_uuid.remove(user);
        _ = self.uuid_to_job.remove(&uuid);
        Some(uuid)
    }

    async fn kill(&self, user: &User) -> Option<Uuid> {
        let job = self.by_user(user)?;
        let uuid = job.read().await.uuid;
        job.write().await.kill().await;
        Some(uuid)
    }

    pub(crate) fn by_user(&self, user: &User) -> Option<&Arc<RwLock<Job>>> {
        self.user_to_job_uuid
            .get(user)
            .and_then(|uuid| self.uuid_to_job.get(uuid))
    }
}
