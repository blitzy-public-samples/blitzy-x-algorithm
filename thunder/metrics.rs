//! Metrics definitions for the Thunder service.
//!
//! Provides Prometheus-compatible metric types for monitoring Kafka consumers,
//! PostStore operations, and gRPC request handling. Metrics are exposed as
//! lazy-initialized global statics using `std::sync::LazyLock`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Metric type abstractions (lightweight Prometheus-compatible stubs)
// ---------------------------------------------------------------------------

/// A monotonically increasing counter metric.
#[derive(Debug, Clone)]
pub struct Counter {
    value: Arc<AtomicU64>,
}

impl Counter {
    /// Create a new counter initialized to zero.
    pub fn new() -> Self {
        Self {
            value: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Increment the counter by one.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Return the current counter value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

/// A gauge metric that can go up and down.
#[derive(Debug, Clone)]
pub struct Gauge {
    /// Store as raw u64 bits of an f64.
    bits: Arc<AtomicU64>,
}

impl Gauge {
    /// Create a new gauge initialized to zero.
    pub fn new() -> Self {
        Self {
            bits: Arc::new(AtomicU64::new(0f64.to_bits())),
        }
    }

    /// Set the gauge to the given value.
    pub fn set(&self, val: f64) {
        self.bits.store(val.to_bits(), Ordering::Relaxed);
    }

    /// Increment the gauge by one.
    pub fn inc(&self) {
        let current = f64::from_bits(self.bits.load(Ordering::Relaxed));
        self.bits
            .store((current + 1.0).to_bits(), Ordering::Relaxed);
    }

    /// Decrement the gauge by one.
    pub fn dec(&self) {
        let current = f64::from_bits(self.bits.load(Ordering::Relaxed));
        self.bits
            .store((current - 1.0).to_bits(), Ordering::Relaxed);
    }

    /// Return the current gauge value.
    pub fn get(&self) -> f64 {
        f64::from_bits(self.bits.load(Ordering::Relaxed))
    }
}

impl Default for Gauge {
    fn default() -> Self {
        Self::new()
    }
}

/// A histogram metric that records observed values.
#[derive(Debug, Clone)]
pub struct Histogram {
    observations: Arc<Mutex<Vec<f64>>>,
}

impl Histogram {
    /// Create a new empty histogram.
    pub fn new() -> Self {
        Self {
            observations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record a single observation.
    pub fn observe(&self, val: f64) {
        if let Ok(mut obs) = self.observations.lock() {
            obs.push(val);
        }
    }

    /// Return all recorded observations.
    pub fn get_observations(&self) -> Vec<f64> {
        self.observations
            .lock()
            .map(|obs| obs.clone())
            .unwrap_or_default()
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

/// A gauge vector with string labels.
#[derive(Debug, Clone)]
pub struct GaugeVec {
    entries: Arc<Mutex<std::collections::HashMap<Vec<String>, Gauge>>>,
}

impl GaugeVec {
    /// Create a new gauge vector.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Return a [`Gauge`] for the given label values, creating it if absent.
    pub fn with_label_values(&self, labels: &[&str]) -> Gauge {
        let key: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(key).or_insert_with(Gauge::new).clone()
    }
}

impl Default for GaugeVec {
    fn default() -> Self {
        Self::new()
    }
}

/// A histogram vector with string labels.
#[derive(Debug, Clone)]
pub struct HistogramVec {
    entries: Arc<Mutex<std::collections::HashMap<Vec<String>, Histogram>>>,
}

impl HistogramVec {
    /// Create a new histogram vector.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Return a [`Histogram`] for the given label values, creating it if absent.
    pub fn with_label_values(&self, labels: &[&str]) -> Histogram {
        let key: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(key).or_insert_with(Histogram::new).clone()
    }
}

impl Default for HistogramVec {
    fn default() -> Self {
        Self::new()
    }
}

/// A timer that records elapsed time into a [`Histogram`] when dropped.
pub struct Timer {
    histogram: Histogram,
    start: Instant,
}

impl Timer {
    /// Create a new timer that will observe into the given histogram on drop.
    pub fn new(histogram: Histogram) -> Self {
        Self {
            histogram,
            start: Instant::now(),
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        self.histogram.observe(elapsed);
    }
}

// ---------------------------------------------------------------------------
// Global metric instances — Kafka
// ---------------------------------------------------------------------------

/// Partition lag per topic/partition (Gauge with labels `[topic, partition]`).
pub static KAFKA_PARTITION_LAG: LazyLock<GaugeVec> = LazyLock::new(GaugeVec::new);

/// Counter of Kafka poll errors.
pub static KAFKA_POLL_ERRORS: LazyLock<Counter> = LazyLock::new(Counter::new);

/// Counter of Kafka messages that failed to parse.
pub static KAFKA_MESSAGES_FAILED_PARSE: LazyLock<Counter> = LazyLock::new(Counter::new);

/// Histogram of batch processing times (seconds).
pub static BATCH_PROCESSING_TIME: LazyLock<Histogram> = LazyLock::new(Histogram::new);

// ---------------------------------------------------------------------------
// Global metric instances — PostStore
// ---------------------------------------------------------------------------

/// Counter of total PostStore read requests.
pub static POST_STORE_REQUESTS: LazyLock<Counter> = LazyLock::new(Counter::new);

/// Counter of PostStore request timeouts.
pub static POST_STORE_REQUEST_TIMEOUTS: LazyLock<Counter> = LazyLock::new(Counter::new);

/// Counter of deleted posts that were filtered out during reads.
pub static POST_STORE_DELETED_POSTS_FILTERED: LazyLock<Counter> = LazyLock::new(Counter::new);

/// Gauge of total deleted posts in the store.
pub static POST_STORE_DELETED_POSTS: LazyLock<Gauge> = LazyLock::new(Gauge::new);

/// Gauge of total posts in the store.
pub static POST_STORE_TOTAL_POSTS: LazyLock<Gauge> = LazyLock::new(Gauge::new);

/// Gauge of total user count in the store.
pub static POST_STORE_USER_COUNT: LazyLock<Gauge> = LazyLock::new(Gauge::new);

/// GaugeVec of entity counts by category (users, posts, original_posts, etc.).
pub static POST_STORE_ENTITY_COUNT: LazyLock<GaugeVec> = LazyLock::new(GaugeVec::new);

/// Histogram of posts returned per request.
pub static POST_STORE_POSTS_RETURNED: LazyLock<Histogram> = LazyLock::new(Histogram::new);

/// Histogram of the ratio of returned posts to available posts.
pub static POST_STORE_POSTS_RETURNED_RATIO: LazyLock<Histogram> = LazyLock::new(Histogram::new);

// ---------------------------------------------------------------------------
// Global metric instances — gRPC GetInNetworkPosts
// ---------------------------------------------------------------------------

/// Histogram of result count per GetInNetworkPosts call.
pub static GET_IN_NETWORK_POSTS_COUNT: LazyLock<Histogram> = LazyLock::new(Histogram::new);

/// Histogram of total request duration (including Strato calls).
pub static GET_IN_NETWORK_POSTS_DURATION: LazyLock<Histogram> = LazyLock::new(Histogram::new);

/// Histogram of request duration excluding Strato fetch time.
pub static GET_IN_NETWORK_POSTS_DURATION_WITHOUT_STRATO: LazyLock<Histogram> =
    LazyLock::new(Histogram::new);

/// Histogram of the number of following user IDs in each request.
pub static GET_IN_NETWORK_POSTS_FOLLOWING_SIZE: LazyLock<Histogram> =
    LazyLock::new(Histogram::new);

/// Histogram of the number of excluded tweet IDs in each request.
pub static GET_IN_NETWORK_POSTS_EXCLUDED_SIZE: LazyLock<Histogram> =
    LazyLock::new(Histogram::new);

/// Histogram of max_results parameter per request.
pub static GET_IN_NETWORK_POSTS_MAX_RESULTS: LazyLock<Histogram> = LazyLock::new(Histogram::new);

/// HistogramVec of post freshness (seconds since most recent post) by stage.
pub static GET_IN_NETWORK_POSTS_FOUND_FRESHNESS_SECONDS: LazyLock<HistogramVec> =
    LazyLock::new(HistogramVec::new);

/// HistogramVec of time range (oldest - newest) by stage.
pub static GET_IN_NETWORK_POSTS_FOUND_TIME_RANGE_SECONDS: LazyLock<HistogramVec> =
    LazyLock::new(HistogramVec::new);

/// HistogramVec of reply ratio by stage.
pub static GET_IN_NETWORK_POSTS_FOUND_REPLY_RATIO: LazyLock<HistogramVec> =
    LazyLock::new(HistogramVec::new);

/// HistogramVec of unique author count by stage.
pub static GET_IN_NETWORK_POSTS_FOUND_UNIQUE_AUTHORS: LazyLock<HistogramVec> =
    LazyLock::new(HistogramVec::new);

/// HistogramVec of posts-per-author ratio by stage.
pub static GET_IN_NETWORK_POSTS_FOUND_POSTS_PER_AUTHOR: LazyLock<HistogramVec> =
    LazyLock::new(HistogramVec::new);

/// Gauge of currently in-flight requests.
pub static IN_FLIGHT_REQUESTS: LazyLock<Gauge> = LazyLock::new(Gauge::new);

/// Counter of rejected (load-shed) requests.
pub static REJECTED_REQUESTS: LazyLock<Counter> = LazyLock::new(Counter::new);
