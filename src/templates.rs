// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::auth::Url;

use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use enarx_config::Protocol;

#[derive(Template)]
#[template(path = "idx.html")]
pub struct IdxTemplate<'a> {
    pub toml: &'static str,
    pub examples: &'a [&'static str],
    pub user: bool,
    pub star: bool,
    pub size: usize,
    pub size_human: String,
    pub ttl: u64,
}

#[derive(Template)]
#[template(path = "job.html")]
pub struct JobTemplate<'a> {
    pub url: &'a Url,
    pub listen_ports: &'a [(u16, Protocol)],
}

impl<'a> JobTemplate<'a> {
    pub fn create_url(&self, port: &&u16) -> String {
        let mut url = self.url.clone();
        let _ = url.set_port(Some(**port));
        url.to_string()
    }
}

pub struct HtmlTemplate<T>(pub T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {}", err),
            )
                .into_response(),
        }
    }
}
