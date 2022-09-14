use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Example {
    pub(crate) disabled: Option<bool>,
    pub(crate) slug: String,
    pub(crate) url: String,
    pub(crate) description: String,
}

impl fmt::Display for Example {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", self)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Examples {
    examples: Vec<Example>,
}

impl Deref for Examples {
    type Target = Vec<Example>;

    fn deref(&self) -> &Self::Target {
        &self.examples
    }
}

impl FromStr for Examples {
    type Err = toml::de::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        toml::from_str(s)
    }
}

impl Default for Examples {
    fn default() -> Examples {
        let examples = vec![
            Example {
                disabled: None,
                slug: "examples/cryptle-rust:0.2.0".to_string(),
                url: "https://github.com/enarx/cryptle/tree/v0.2.0".to_string(),
                description: "A secure multi-party Wordle clone.".to_string()
            },
            Example {
                disabled: None,
                slug: "examples/echo-tcp-rust-mio:0.2.0".to_string(),
                url: "https://github.com/enarx/codex/tree/v0.1.0/Rust/mio-echo-tcp".to_string(),
                description: r#"A TCP Echo server using <a href="https://github.com/tokio-rs/tokio" target="_blank">tokio</a>."#.to_string()
            },
            Example {
                disabled: None,
                slug: "examples/echo-tcp-rust-tokio:0.2.0".to_string(),
                url: "https://github.com/enarx/codex/tree/v0.1.0/Rust/tokio-echo-tcp".to_string(),
                description: r#"An adapted version of the upstream mio crate tcp_server example using a modified <a href="https://github.com/tokio-rs/mio" target="_blank">mio</a> with WASI support."#.to_string()
            },
            Example {
                disabled: None,
                slug: "examples/fibonacci-cpp:0.3.0".to_string(),
                url: "https://github.com/enarx/codex/tree/v0.1.0/C++/fibonacci".to_string(),
                description: r#"A C++ fibonacci example."#.to_string()
            },
            Example {
                disabled: None,
                slug: "examples/fibonacci-c:0.3.0".to_string(),
                url: "https://github.com/enarx/codex/tree/v0.1.0/C".to_string(),
                description: r#"A C fibonacci example."#.to_string()
            },
            Example {
                disabled: None,
                slug: "examples/fibonacci-go:0.3.0".to_string(),
                url: "https://github.com/enarx/codex/tree/v0.1.0/Go/fibonacci".to_string(),
                description: r#"A Go fibonacci example."#.to_string()
            },
            Example {
                disabled: None,
                slug: "examples/fibonacci-grain:0.1.0".to_string(),
                url: "https://github.com/enarx/codex/tree/v0.1.0/Grain/fibonacci".to_string(),
                description: r#"A Grain fibonacci example."#.to_string()
            },
            Example {
                disabled: None,
                slug: "examples/fibonacci-rust:0.3.0".to_string(),
                url: "https://github.com/enarx/codex/tree/v0.1.0/Rust/fibonacci".to_string(),
                description: r#"A Rust fibonacci example."#.to_string()
            },
            Example {
                disabled: None,
                slug: "examples/fibonacci-zig:0.4.0".to_string(),
                url: "https://github.com/enarx/codex/tree/v0.1.0/Zig/fibonacci".to_string(),
                description: r#"A Zig fibonacci example."#.to_string()
            },
            Example {
                disabled: None,
                slug: "examples/greenhouse-monitor-csharp:0.1.0".to_string(),
                url: "https://github.com/enarx/GreenhouseMonitor/tree/v0.1.0".to_string(),
                description: r#"GreenhouseMonitor is a ASP.NET demo application by Steve Sanderson at Microsoft compiled to WASI via <a href="https://github.com/SteveSandersonMS/dotnet-wasi-sdk" target="_blank">Wasi.Sdk</a>.<br />
<br />
GreenhouseMonitor is licensed under MIT.<br />
Copyright (c) .NET Foundation and Contributors"#.to_string()
            },
            Example {
                disabled: None,
                slug: "examples/http-rust-tokio:0.2.0".to_string(),
                url: "https://github.com/enarx/codex/tree/v0.1.0/Rust/tokio-http".to_string(),
                description: r#"A modified version of the <a href="https://github.com/tokio-rs/tokio/blob/master/examples/tinyhttp.rs" target="_blank">tinyhttp.rs</a> example in the <a href="https://github.com/tokio-rs/tokio" target="_blank">tokio</a> repository."#.to_string()
            },
        ];
        Examples { examples }
    }
}
