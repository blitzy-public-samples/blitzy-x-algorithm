//! Strato client for fetching social graph data (following lists).
//!
//! The StratoClient communicates with the Strato column store to retrieve
//! the list of user IDs that a given user follows.

use anyhow::Result;

/// Client for the Strato column store.
#[derive(Debug, Clone)]
pub struct StratoClient;

impl StratoClient {
    /// Create a new StratoClient instance.
    pub fn new() -> Self {
        Self
    }

    /// Fetch the list of user IDs that `user_id` follows, up to `max_results`.
    ///
    /// Returns a vector of i64 user IDs.
    ///
    /// In the stub environment, this always returns an error because no real
    /// Strato column store service is available. This matches the expected
    /// production behavior when the Strato service is unreachable.
    pub async fn fetch_following_list(
        &self,
        user_id: i64,
        max_results: i32,
    ) -> Result<Vec<i64>> {
        let _ = (user_id, max_results);
        // Stub: simulate network failure — the real implementation would make
        // an internal RPC to the Strato column store.
        Err(anyhow::anyhow!(
            "Strato service unavailable: connection refused to strato-host:9090"
        ))
    }
}

impl Default for StratoClient {
    fn default() -> Self {
        Self::new()
    }
}
