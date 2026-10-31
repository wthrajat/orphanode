//! Opt-in usage analytics and traces. Nothing is sent unless
//! `POSTHOG_PROJECT_TOKEN` is set, and then only to that project.

use std::sync::Arc;

use posthog_rs::mcp::{Identity, McpAnalytics, McpOptions, McpOptionsBuilder};

pub(super) struct Settings {
    pub(super) token: String,
    pub(super) host: String,
    /// Optional person for the agent's tool calls, from `POSTHOG_DISTINCT_ID`.
    distinct_id: Option<String>,
}

impl Settings {
    pub(super) fn from_env() -> Option<Self> {
        Some(Self {
            token: env_value("POSTHOG_PROJECT_TOKEN")?,
            host: env_value("POSTHOG_HOST").unwrap_or_else(|| posthog_rs::DEFAULT_HOST.to_owned()),
            distinct_id: env_value("POSTHOG_DISTINCT_ID"),
        })
    }
}

pub(super) async fn client(settings: &Settings) -> Option<Arc<posthog_rs::Client>> {
    let options = posthog_rs::ClientOptionsBuilder::default()
        .api_key(settings.token.clone())
        .host(settings.host.as_str())
        .disable_geoip(true)
        .build()
        .ok()?;
    Some(Arc::new(posthog_rs::client(options).await))
}

pub(super) fn mcp_analytics(client: Arc<posthog_rs::Client>, settings: &Settings) -> McpAnalytics {
    McpAnalytics::new(client, mcp_options(settings))
}

fn mcp_options(settings: &Settings) -> McpOptions {
    let mut options = McpOptionsBuilder::default();
    if let Some(distinct_id) = settings.distinct_id.clone() {
        options.identify(move |_| Some(Identity::new(distinct_id.as_str())));
    }
    options.build().unwrap_or_default()
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}
