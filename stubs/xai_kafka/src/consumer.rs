//! Kafka consumer abstractions.

use crate::config::KafkaConsumerConfig;
use crate::KafkaMessage;

/// Partition lag information for monitoring.
#[derive(Debug, Clone)]
pub struct PartitionLag {
    pub partition_id: i32,
    pub lag: i64,
}

/// Kafka consumer that reads messages from a Kafka topic.
#[derive(Debug)]
pub struct KafkaConsumer {
    _config: KafkaConsumerConfig,
}

impl KafkaConsumer {
    pub fn new(config: KafkaConsumerConfig) -> Self {
        Self { _config: config }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn poll(&self, _batch_size: usize) -> anyhow::Result<Vec<KafkaMessage>> {
        Ok(Vec::new())
    }

    pub async fn commit(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn commit_offsets(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn get_partition_lags(&self) -> anyhow::Result<Vec<PartitionLag>> {
        Ok(Vec::new())
    }
}
