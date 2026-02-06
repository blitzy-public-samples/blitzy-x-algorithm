//! Schema definitions for Thunder Kafka event processing.
//!
//! These types model the Thrift-generated structures used for tweet event
//! deserialization in the Kafka consumer pipeline.

pub mod events;
pub mod tweet;
pub mod tweet_events;
pub mod tweet_media;
