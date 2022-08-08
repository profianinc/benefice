// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::jobs::Job;

#[derive(Debug, Default)]
pub(crate) struct Data {
    job: Option<Job>,
}

impl Data {
    pub(crate) fn new(job: Option<Job>) -> Self {
        Self { job }
    }

    pub(crate) fn job(&self) -> &Option<Job> {
        &self.job
    }

    pub(crate) fn job_mut(&mut self) -> Option<&mut Job> {
        self.job.as_mut()
    }

    pub(crate) async fn kill_job(&mut self) {
        if let Some(job) = &mut self.job {
            job.kill().await;
        }

        self.job = None;
    }
}
