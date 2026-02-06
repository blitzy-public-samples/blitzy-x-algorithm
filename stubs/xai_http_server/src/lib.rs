//! Stub crate for xai_http_server — provides HTTP/gRPC server infrastructure.

use std::time::Duration;

/// Token for cooperative cancellation of background tasks.
#[derive(Debug, Clone)]
pub struct CancellationToken;

impl CancellationToken {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// gRPC routing configuration.
pub struct GrpcConfig;

impl GrpcConfig {
    pub fn new(_port: u16, _routes: tonic::service::Routes) -> Self {
        Self
    }
}

/// Combined HTTP + gRPC server.
pub struct HttpServer;

impl HttpServer {
    pub async fn new(
        _http_port: u16,
        _router: axum::Router,
        _grpc_config: Option<GrpcConfig>,
        _cancellation_token: CancellationToken,
        _shutdown_timeout: Duration,
    ) -> anyhow::Result<Self> {
        Ok(Self)
    }

    pub fn set_readiness(&mut self, _ready: bool) {}

    pub async fn wait_for_termination(&self) {
        tokio::signal::ctrl_c().await.ok();
    }
}
