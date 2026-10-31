//! Sends orphanode's spans to `PostHog` Tracing. `posthog-rs-otel` stamps each
//! span with the session, and person when identified, of the tool call that
//! ran it, so a trace joins that call's `$mcp_tool_call` event.

use std::collections::HashMap;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use posthog_rs_otel::PostHogContextSpanProcessor;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use super::analytics::Settings;

const SERVICE_NAME: &str = "orphanode";

/// Returns `None` when tracing can't start; the tools still work without it.
pub(super) fn install(
    client: &posthog_rs::Client,
    settings: &Settings,
) -> Option<SdkTracerProvider> {
    let provider = SdkTracerProvider::builder()
        .with_span_processor(PostHogContextSpanProcessor::new(client))
        .with_batch_exporter(exporter(settings)?)
        .with_resource(Resource::builder().with_service_name(SERVICE_NAME).build())
        .build();
    let orphanode_spans_only = Targets::new().with_target("orphanode", tracing::Level::INFO);
    let otel_layer = tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(SERVICE_NAME))
        .with_filter(orphanode_spans_only);
    tracing_subscriber::registry()
        .with(otel_layer)
        .try_init()
        .ok()?;
    Some(provider)
}

pub(super) async fn shutdown(provider: SdkTracerProvider) {
    let _ = tokio::task::spawn_blocking(move || provider.shutdown()).await;
}

fn exporter(settings: &Settings) -> Option<SpanExporter> {
    let endpoint = format!("{}/i/v1/traces", settings.host.trim_end_matches('/'));
    let authorization = format!("Bearer {}", settings.token);
    SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpJson)
        .with_endpoint(endpoint)
        .with_headers(HashMap::from([("Authorization".to_owned(), authorization)]))
        .build()
        .ok()
}
