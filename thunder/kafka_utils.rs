use anyhow::{Context, Result};
use std::sync::Arc;
use xai_kafka::KafkaProducerConfig;
use xai_kafka::config::{KafkaConfig, KafkaConsumerConfig, SslConfig};
use xai_wily::WilyConfig;

use crate::{
    args,
    kafka::{
        tweet_events_listener::start_tweet_event_processing,
        tweet_events_listener_v2::start_tweet_event_processing_v2,
    },
};

// [C-2] Security Fix (CWE-1188 / OWASP A02:2025): Kafka topic and destination
// constants are now loaded from environment variables at first access.
// Previously, these were empty strings ("") which caused Kafka consumers to
// subscribe to nothing and producers to route messages nowhere, silently
// dropping all event ingestion. Startup will panic if any required topic
// variable is unset, preventing silent misconfiguration in production.
lazy_static::lazy_static! {
    static ref TWEET_EVENT_TOPIC: String = std::env::var("KAFKA_TWEET_EVENT_TOPIC")
        .expect("KAFKA_TWEET_EVENT_TOPIC environment variable must be set");
    static ref TWEET_EVENT_DEST: String = std::env::var("KAFKA_TWEET_EVENT_DEST")
        .expect("KAFKA_TWEET_EVENT_DEST environment variable must be set");
    static ref IN_NETWORK_EVENTS_DEST: String = std::env::var("KAFKA_IN_NETWORK_EVENTS_DEST")
        .expect("KAFKA_IN_NETWORK_EVENTS_DEST environment variable must be set");
    static ref IN_NETWORK_EVENTS_TOPIC: String = std::env::var("KAFKA_IN_NETWORK_EVENTS_TOPIC")
        .expect("KAFKA_IN_NETWORK_EVENTS_TOPIC environment variable must be set");
}

pub async fn start_kafka(
    args: &args::Args,
    post_store: Arc<crate::posts::post_store::PostStore>,
    user: &str,
    tx: tokio::sync::mpsc::Sender<i64>,
) -> Result<()> {
    // [M-7] Security Fix (CWE-287 / OWASP A07:2025): Validate that the SASL
    // username is non-empty. An empty username weakens Kafka authentication
    // and may cause silent connection failures or fall back to unauthenticated
    // access depending on the Kafka broker configuration.
    if user.is_empty() {
        log::warn!(
            "SASL username is empty - Kafka authentication may fail. \
             Ensure a valid SASL username is provided via configuration."
        );
    }

    // [C-1] Security Fix (CWE-1188 / OWASP A02:2025): Replace empty-string
    // environment variable lookups with properly named variables. Previously,
    // `std::env::var("")` always returned `Err(NotPresent)` because the env
    // var name was an empty string, causing SASL passwords to silently default
    // to empty values — a complete authentication bypass.
    let sasl_password = std::env::var("KAFKA_SASL_PASSWORD")
        .ok()
        .or(args.sasl_password.clone())?;

    // [C-1] Security Fix: Same pattern for producer SASL password.
    let producer_sasl_password = std::env::var("KAFKA_PRODUCER_SASL_PASSWORD")
        .ok()
        .or(args.producer_sasl_password.clone());

    if args.is_serving {
        let unique_id = uuid::Uuid::new_v4().to_string();

        let v2_tweet_events_consumer_config = KafkaConsumerConfig {
            base_config: KafkaConfig {
                dest: args.in_network_events_consumer_dest.clone(),
                topic: IN_NETWORK_EVENTS_TOPIC.clone(),
                wily_config: Some(WilyConfig::default()),
                ssl: Some(SslConfig {
                    security_protocol: args.security_protocol.clone(),
                    sasl_mechanism: Some(args.producer_sasl_mechanism.clone()),
                    sasl_username: Some(args.producer_sasl_username.clone()),
                    sasl_password: producer_sasl_password.clone(),
                }),
                ..Default::default()
            },
            group_id: format!("{}-{}", args.kafka_group_id, unique_id),
            auto_offset_reset: args.auto_offset_reset.clone(),
            fetch_timeout_ms: args.fetch_timeout_ms,
            max_partition_fetch_bytes: Some(1024 * 1024 * 100),
            skip_to_latest: args.skip_to_latest,
            ..Default::default()
        };

        // Start Kafka background tasks
        start_tweet_event_processing_v2(
            v2_tweet_events_consumer_config,
            Arc::clone(&post_store),
            args,
            tx,
        )
        .await;
    }

    // Only start Kafka processing and background tasks if not in serving mode
    if !args.is_serving {
        // Create Kafka consumer config
        let tweet_events_consumer_config = KafkaConsumerConfig {
            base_config: KafkaConfig {
                dest: TWEET_EVENT_DEST.clone(),
                topic: TWEET_EVENT_TOPIC.clone(),
                wily_config: Some(WilyConfig::default()),
                ssl: Some(SslConfig {
                    security_protocol: args.security_protocol.clone(),
                    sasl_mechanism: Some(args.sasl_mechanism.clone()),
                    sasl_username: Some(args.sasl_username.clone()),
                    sasl_password: Some(sasl_password.clone()),
                }),
                ..Default::default()
            },
            group_id: format!("{}-{}", args.kafka_group_id, user),
            auto_offset_reset: args.auto_offset_reset.clone(),
            enable_auto_commit: false,
            fetch_timeout_ms: args.fetch_timeout_ms,
            max_partition_fetch_bytes: Some(1024 * 1024 * 10),
            partitions: None,
            skip_to_latest: args.skip_to_latest,
            ..Default::default()
        };

        let producer_config = KafkaProducerConfig {
            base_config: KafkaConfig {
                dest: IN_NETWORK_EVENTS_DEST.clone(),
                topic: IN_NETWORK_EVENTS_TOPIC.clone(),
                wily_config: Some(WilyConfig::default()),
                ssl: Some(SslConfig {
                    security_protocol: args.security_protocol.clone(),
                    sasl_mechanism: Some(args.producer_sasl_mechanism.clone()),
                    sasl_username: Some(args.producer_sasl_username.clone()),
                    sasl_password: producer_sasl_password.clone(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        start_tweet_event_processing(tweet_events_consumer_config, producer_config, args).await;
    }

    Ok(())
}
