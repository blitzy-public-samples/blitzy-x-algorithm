//! Tweet schema definitions (Thrift-generated equivalents).

use super::tweet_media::MediaEntity;

/// Represents a reply relationship.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    pub in_reply_to_status_id: Option<i64>,
    pub in_reply_to_user_id: Option<i64>,
}

/// Represents a retweet/share relationship.
#[derive(Debug, Clone, Default)]
pub struct Share {
    pub source_status_id: Option<i64>,
    pub source_user_id: Option<i64>,
}

/// Core data fields of a tweet.
#[derive(Debug, Clone, Default)]
pub struct TweetCoreData {
    pub created_at_secs: Option<i64>,
    pub reply: Option<Reply>,
    pub share: Option<Share>,
    pub conversation_id: Option<i64>,
    pub nullcast: Option<bool>,
}

/// A tweet object from the Thrift schema.
#[derive(Debug, Clone, Default)]
pub struct Tweet {
    pub id: Option<i64>,
    pub core_data: Option<TweetCoreData>,
    pub media: Option<Vec<MediaEntity>>,
}

/// A user object from the Thrift schema.
#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: Option<i64>,
}
