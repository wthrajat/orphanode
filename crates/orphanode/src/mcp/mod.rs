//! `orphanode mcp`: the scan and why commands as tools for coding agents.

mod analytics;
mod arguments;
mod reply;
mod server;
mod traces;

use std::process::ExitCode;

use rmcp::{ServerHandler, ServiceExt, transport::stdio};

use crate::CliError;
use server::OrphanodeTools;

pub(crate) fn run() -> Result<ExitCode, CliError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::Mcp(error.to_string()))?;
    runtime
        .block_on(serve())
        .map_err(|error| CliError::Mcp(error.to_string()))?;
    Ok(ExitCode::SUCCESS)
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let Some(settings) = analytics::Settings::from_env() else {
        return serve_until_closed(OrphanodeTools).await;
    };
    let Some(posthog) = analytics::client(&settings).await else {
        return serve_until_closed(OrphanodeTools).await;
    };
    let tracer_provider = traces::install(&posthog, &settings);
    let tools = analytics::mcp_analytics(posthog.clone(), &settings).instrument(OrphanodeTools);
    let outcome = serve_until_closed(tools).await;
    posthog.shutdown().await;
    if let Some(tracer_provider) = tracer_provider {
        traces::shutdown(tracer_provider).await;
    }
    outcome
}

async fn serve_until_closed(tools: impl ServerHandler) -> Result<(), Box<dyn std::error::Error>> {
    tools.serve(stdio()).await?.waiting().await?;
    Ok(())
}
