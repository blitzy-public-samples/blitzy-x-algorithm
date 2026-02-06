//! Tweet event schema definitions (Thrift-generated equivalents).
//!
//! Represents the Kafka event envelope for tweet lifecycle events.

use super::tweet::{Tweet, User};
use thrift::protocol::{TBinaryInputProtocol, TSerializable};

/// The inner event data (create / delete / quoted-delete).
#[derive(Debug, Clone)]
pub enum TweetEventData {
    /// A new tweet was created.
    TweetCreateEvent(TweetCreateEventData),
    /// A tweet was deleted.
    TweetDeleteEvent(TweetDeleteEventData),
    /// A quote-tweet was deleted.
    QuotedTweetDeleteEvent(QuotedTweetDeleteEventData),
}

/// Data payload for a tweet creation event.
#[derive(Debug, Clone, Default)]
pub struct TweetCreateEventData {
    pub tweet: Option<Tweet>,
    pub user: Option<User>,
}

/// Data payload for a tweet deletion event.
#[derive(Debug, Clone, Default)]
pub struct TweetDeleteEventData {
    pub tweet: Option<Tweet>,
}

/// Data payload for a quoted-tweet deletion event.
#[derive(Debug, Clone, Default)]
pub struct QuotedTweetDeleteEventData {
    pub quoting_tweet_id: Option<i64>,
}

/// Top-level Kafka event envelope for tweet events.
#[derive(Debug, Clone)]
pub struct TweetEvent {
    pub data: Option<TweetEventData>,
}

impl TSerializable for TweetEvent {
    fn read_from_in_protocol<R: std::io::Read>(
        _protocol: &mut TBinaryInputProtocol<R>,
    ) -> std::io::Result<Self> {
        // Stub: return an empty event — real implementation is Thrift-generated.
        Ok(TweetEvent { data: None })
    }
}
