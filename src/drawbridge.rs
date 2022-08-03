use crate::HTTP;

use serde::Deserialize;
use std::fmt;

#[derive(Debug, Deserialize)]
pub struct Slug {
    repo: String,
    tag: String,
}

impl Slug {
    pub fn new(slug: String) -> Option<Self> {
        slug.split_once(':').map(|(repo, tag)| Slug {
            repo: repo.to_string(),
            tag: tag.to_string(),
        })
    }

    pub async fn read(&self, path: &str) -> Result<reqwest::Response, reqwest::Error> {
        HTTP.get(&format!(
            "https://store.profian.com/api/v0.2.0/{}/_tag/{}/tree/{path}",
            self.repo, self.tag
        ))
        .send()
        .await
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.repo, self.tag)
    }
}
