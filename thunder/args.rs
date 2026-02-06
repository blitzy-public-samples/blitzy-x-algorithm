//! Command-line argument definitions for Thunder service.

use clap::Parser;

/// Thunder service command-line arguments.
#[derive(Debug, Clone, Parser)]
#[command(name = "thunder", about = "Thunder in-network post retrieval service")]
pub struct Args {
    #[arg(long, default_value_t = 86400)]
    pub post_retention_seconds: u64,

    #[arg(long, default_value_t = 5000)]
    pub request_timeout_ms: u64,

    #[arg(long, default_value_t = 100)]
    pub max_concurrent_requests: usize,

    #[arg(long, default_value_t = 50051)]
    pub grpc_port: u16,

    #[arg(long, default_value_t = 8080)]
    pub http_port: u16,

    #[arg(long, default_value_t = false)]
    pub enable_profiling: bool,

    #[arg(long, default_value_t = 4)]
    pub kafka_num_threads: usize,

    #[arg(long, default_value_t = false)]
    pub is_serving: bool,

    #[arg(long, default_value = "")]
    pub sasl_username: String,

    #[arg(long)]
    pub sasl_password: Option<String>,

    #[arg(long)]
    pub producer_sasl_password: Option<String>,

    #[arg(long, default_value = "")]
    pub in_network_events_consumer_dest: String,

    #[arg(long, default_value = "SASL_SSL")]
    pub security_protocol: String,

    #[arg(long, default_value = "SCRAM-SHA-256")]
    pub sasl_mechanism: String,

    #[arg(long, default_value = "SCRAM-SHA-256")]
    pub producer_sasl_mechanism: String,

    #[arg(long, default_value = "")]
    pub producer_sasl_username: String,

    #[arg(long, default_value = "thunder")]
    pub kafka_group_id: String,

    #[arg(long, default_value = "latest")]
    pub auto_offset_reset: String,

    #[arg(long, default_value_t = 5000)]
    pub fetch_timeout_ms: u64,

    #[arg(long, default_value_t = false)]
    pub skip_to_latest: bool,

    #[arg(long, default_value_t = 16)]
    pub tweet_events_num_partitions: u32,

    #[arg(long, default_value_t = 16)]
    pub kafka_tweet_events_v2_num_partitions: usize,

    #[arg(long, default_value_t = 30)]
    pub lag_monitor_interval_secs: u64,

    #[arg(long, default_value_t = 1000)]
    pub kafka_batch_size: usize,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            post_retention_seconds: 86400,
            request_timeout_ms: 5000,
            max_concurrent_requests: 100,
            grpc_port: 50051,
            http_port: 8080,
            enable_profiling: false,
            kafka_num_threads: 4,
            is_serving: false,
            sasl_username: String::new(),
            sasl_password: None,
            producer_sasl_password: None,
            in_network_events_consumer_dest: String::new(),
            security_protocol: String::from("SASL_SSL"),
            sasl_mechanism: String::from("SCRAM-SHA-256"),
            producer_sasl_mechanism: String::from("SCRAM-SHA-256"),
            producer_sasl_username: String::new(),
            kafka_group_id: String::from("thunder"),
            auto_offset_reset: String::from("latest"),
            fetch_timeout_ms: 5000,
            skip_to_latest: false,
            tweet_events_num_partitions: 16,
            kafka_tweet_events_v2_num_partitions: 16,
            lag_monitor_interval_secs: 30,
            kafka_batch_size: 1000,
        }
    }
}
