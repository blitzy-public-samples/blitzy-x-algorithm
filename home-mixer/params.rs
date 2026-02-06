/// Home Mixer configuration parameters — excluded from open source release for security reasons.
/// These constants control pipeline behavior, scoring weights, and resource limits.

// ── gRPC and server configuration ───────────────────────────────────────────

/// Maximum gRPC message size in bytes (50 MB).
pub const MAX_GRPC_MESSAGE_SIZE: usize = 50 * 1024 * 1024;

// ── Pipeline configuration ──────────────────────────────────────────────────

/// Maximum post age in seconds (48 hours).
pub const MAX_POST_AGE: u64 = 48 * 60 * 60;

/// Number of results to return from the pipeline.
pub const RESULT_SIZE: usize = 100;

/// Number of top-K candidates to select before post-selection stages.
pub const TOP_K_CANDIDATES_TO_SELECT: usize = 200;

// ── Source configuration ────────────────────────────────────────────────────

/// Maximum results to retrieve from Phoenix retrieval source.
pub const PHOENIX_MAX_RESULTS: usize = 500;

/// Maximum results to retrieve from Thunder (in-network) source.
pub const THUNDER_MAX_RESULTS: u32 = 500;

// ── User Action Sequence configuration ──────────────────────────────────────

/// Window time in milliseconds for user action sequence aggregation.
pub const UAS_WINDOW_TIME_MS: u64 = 1000;

/// Maximum length of the user action sequence after truncation.
pub const UAS_MAX_SEQUENCE_LENGTH: usize = 200;

// ── Scoring weights ─────────────────────────────────────────────────────────

pub const FAVORITE_WEIGHT: f64 = 1.0;
pub const REPLY_WEIGHT: f64 = 11.0;
pub const RETWEET_WEIGHT: f64 = 1.0;
pub const PHOTO_EXPAND_WEIGHT: f64 = 0.005;
pub const CLICK_WEIGHT: f64 = 0.01;
pub const PROFILE_CLICK_WEIGHT: f64 = 10.0;
pub const VQV_WEIGHT: f64 = 0.0;
pub const SHARE_WEIGHT: f64 = 1.0;
pub const SHARE_VIA_DM_WEIGHT: f64 = 1.0;
pub const SHARE_VIA_COPY_LINK_WEIGHT: f64 = 1.0;
pub const DWELL_WEIGHT: f64 = 0.0;
pub const QUOTE_WEIGHT: f64 = 11.0;
pub const QUOTED_CLICK_WEIGHT: f64 = 0.0;
pub const CONT_DWELL_TIME_WEIGHT: f64 = 0.005;
pub const FOLLOW_AUTHOR_WEIGHT: f64 = 100.0;
pub const NOT_INTERESTED_WEIGHT: f64 = -74.0;
pub const BLOCK_AUTHOR_WEIGHT: f64 = -74.0;
pub const MUTE_AUTHOR_WEIGHT: f64 = -74.0;
pub const REPORT_WEIGHT: f64 = -369.0;

/// Sum of all positive scoring weights, used for normalization.
pub const WEIGHTS_SUM: f64 = FAVORITE_WEIGHT
    + REPLY_WEIGHT
    + RETWEET_WEIGHT
    + PHOTO_EXPAND_WEIGHT
    + CLICK_WEIGHT
    + PROFILE_CLICK_WEIGHT
    + VQV_WEIGHT
    + SHARE_WEIGHT
    + SHARE_VIA_DM_WEIGHT
    + SHARE_VIA_COPY_LINK_WEIGHT
    + DWELL_WEIGHT
    + QUOTE_WEIGHT
    + QUOTED_CLICK_WEIGHT
    + CONT_DWELL_TIME_WEIGHT
    + FOLLOW_AUTHOR_WEIGHT;

/// Sum of negative scoring weights (negative engagement signals).
pub const NEGATIVE_WEIGHTS_SUM: f64 =
    NOT_INTERESTED_WEIGHT + BLOCK_AUTHOR_WEIGHT + MUTE_AUTHOR_WEIGHT + REPORT_WEIGHT;

/// Offset applied to shift negative scores into a positive range.
pub const NEGATIVE_SCORES_OFFSET: f64 = 400.0;

// ── Scorer configuration ────────────────────────────────────────────────────

/// Minimum video duration in milliseconds for VQV scoring eligibility.
pub const MIN_VIDEO_DURATION_MS: i32 = 10_000;

/// Out-of-network weight factor applied to OON candidates.
pub const OON_WEIGHT_FACTOR: f64 = 0.5;

/// Decay factor for author diversity scorer.
pub const AUTHOR_DIVERSITY_DECAY: f64 = 0.5;

/// Floor value for author diversity scorer.
pub const AUTHOR_DIVERSITY_FLOOR: f64 = 0.1;
