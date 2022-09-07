// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

pub(crate) enum Page {
    Examples,
    Drawbridge,
    Upload,
}

#[derive(Template)]
#[template(path = "idx.html")]
pub(crate) struct IdxTemplate<'a> {
    pub(crate) demo_fqdn: String,
    pub(crate) page: Page,
    pub(crate) toml: &'static str,
    pub(crate) examples: &'a [&'static str],
    pub(crate) user: bool,
    pub(crate) star: bool,
    pub(crate) _size: usize,
    pub(crate) size_human: String,
    pub(crate) ttl: u64,
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
