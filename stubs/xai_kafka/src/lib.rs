//! Stub crate for xai_kafka — provides Kafka consumer/producer abstractions.

pub mod config;
pub mod consumer;

pub use config::{KafkaConfig, KafkaConsumerConfig, KafkaProducerConfig, SslConfig};
pub use consumer::KafkaConsumer;

/// Represents a single Kafka message with optional payload.
#[derive(Debug, Clone, Default)]
pub struct KafkaMessage {
    pub payload: Option<Vec<u8>>,
    pub key: Option<Vec<u8>>,
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
}

/// Kafka producer handle.
#[derive(Debug, Clone)]
pub struct KafkaProducer {
    _config: KafkaProducerConfig,
}

impl KafkaProducer {
    pub fn new(config: KafkaProducerConfig) -> Self {
        Self { _config: config }
    }

    /// Start the producer (connect to Kafka cluster).
    pub async fn start(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Send a payload to the configured topic.
    pub async fn send(&self, _payload: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
}
