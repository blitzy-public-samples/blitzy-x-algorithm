//! Configuration constants for the Thunder service.

/// Maximum number of items allowed in following/exclude input lists.
pub const MAX_INPUT_LIST_SIZE: usize = 5000;

/// Maximum number of posts to return in a non-video request.
pub const MAX_POSTS_TO_RETURN: usize = 500;

/// Maximum number of video posts to return.
pub const MAX_VIDEOS_TO_RETURN: usize = 100;

/// Maximum original (non-reply, non-retweet) posts per author to consider.
pub const MAX_ORIGINAL_POSTS_PER_AUTHOR: usize = 50;

/// Maximum reply/retweet posts per author to consider.
pub const MAX_REPLY_POSTS_PER_AUTHOR: usize = 20;

/// Maximum video posts per author to consider.
pub const MAX_VIDEO_POSTS_PER_AUTHOR: usize = 10;

/// Maximum number of TinyPost entries to scan per user.
pub const MAX_TINY_POSTS_PER_USER_SCAN: usize = 200;

/// Special key in the posts-by-user map used to track delete events.
pub const DELETE_EVENT_KEY: i64 = -1;

/// Minimum video duration in milliseconds for video eligibility.
pub const MIN_VIDEO_DURATION_MS: i64 = 1000;
