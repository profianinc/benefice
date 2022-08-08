// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::EXAMPLES;

use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

#[derive(Template)]
#[template(path = "idx.html")]
pub(crate) struct IdxTemplate<'a> {
    pub(crate) toml: &'static str,
    pub(crate) examples: &'a [&'static str],
    pub(crate) user: bool,
    pub(crate) star: bool,
    pub(crate) size_human: String,
    pub(crate) ttl: u64,
}

#[derive(Template)]
#[template(path = "job.html")]
pub(crate) struct JobTemplate;

impl JobTemplate {
    fn get_slug_url(&self, slug: &str) -> String {
        for example_slug in &*EXAMPLES {
            if example_slug.contains(slug) {
                return format!("/?slug={}", example_slug);
            }
        }

        panic!("Slug {slug} not found in examples");
    }
}

pub(crate) struct HtmlTemplate<T>(pub(crate) T);

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
