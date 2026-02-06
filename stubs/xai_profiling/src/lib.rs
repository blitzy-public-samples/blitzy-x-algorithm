//! Stub crate for xai_profiling — provides a profiling/metrics server.

use xai_http_server::CancellationToken;

/// Spawn a profiling server on the given port.
pub async fn spawn_server(_port: u16, _cancellation_token: CancellationToken) {
    // Stub: no-op
}
