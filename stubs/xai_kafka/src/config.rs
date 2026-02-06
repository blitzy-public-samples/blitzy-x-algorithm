//! Kafka configuration types.

use xai_wily::WilyConfig;

/// Base Kafka configuration for consumers and producers.
#[derive(Debug, Clone, Default)]
pub struct KafkaConfig {
    pub dest: String,
    pub topic: String,
    pub wily_config: Option<WilyConfig>,
    pub ssl: Option<SslConfig>,
}

/// SSL/SASL configuration for Kafka connections.
#[derive(Debug, Clone, Default)]
pub struct SslConfig {
    pub security_protocol: String,
    pub sasl_mechanism: Option<String>,
    pub sasl_username: Option<String>,
    pub sasl_password: Option<String>,
}

/// Consumer-specific Kafka configuration.
#[derive(Debug, Clone, Default)]
pub struct KafkaConsumerConfig {
    pub base_config: KafkaConfig,
    pub group_id: String,
    pub auto_offset_reset: String,
    pub enable_auto_commit: bool,
    pub fetch_timeout_ms: u64,
    pub max_partition_fetch_bytes: Option<usize>,
    pub partitions: Option<Vec<i32>>,
    pub skip_to_latest: bool,
}

/// Producer-specific Kafka configuration.
#[derive(Debug, Clone, Default)]
pub struct KafkaProducerConfig {
    pub base_config: KafkaConfig,
}
