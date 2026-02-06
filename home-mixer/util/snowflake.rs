/// Snowflake ID utilities for extracting timestamps from tweet IDs.
/// Twitter Snowflake IDs encode a millisecond timestamp in the upper bits.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Twitter Snowflake epoch (November 4, 2010 01:42:54.657 UTC) in milliseconds.
const SNOWFLAKE_EPOCH_MS: u64 = 1288834974657;

/// Extracts the creation timestamp from a Snowflake tweet ID.
/// Returns None if the tweet ID is invalid or if the timestamp cannot be computed.
pub fn duration_since_creation_opt(tweet_id: i64) -> Option<Duration> {
    if tweet_id <= 0 {
        return None;
    }
    let tweet_id = tweet_id as u64;
    let timestamp_ms = (tweet_id >> 22) + SNOWFLAKE_EPOCH_MS;
    let created_at = UNIX_EPOCH + Duration::from_millis(timestamp_ms);
    SystemTime::now().duration_since(created_at).ok()
}
