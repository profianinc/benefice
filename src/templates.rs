// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::EXAMPLES;

use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

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
pub struct JobTemplate;

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
