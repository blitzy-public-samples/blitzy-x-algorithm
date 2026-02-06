// =============================================================================
// xai_recsys_proto — Stub for recommendation system protobuf types.
// =============================================================================

// ── ActionName Enum ─────────────────────────────────────────────────────────

/// Enumeration of discrete user actions used by the Phoenix scoring model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum ActionName {
    ServerTweetFav = 0,
    ServerTweetReply = 1,
    ServerTweetRetweet = 2,
    ClientTweetPhotoExpand = 3,
    ClientTweetClick = 4,
    ClientTweetClickProfile = 5,
    ClientTweetVideoQualityView = 6,
    ClientTweetShare = 7,
    ClientTweetClickSendViaDirectMessage = 8,
    ClientTweetShareViaCopyLink = 9,
    ClientTweetRecapDwelled = 10,
    ServerTweetQuote = 11,
    ClientQuotedTweetClick = 12,
    ClientTweetFollowAuthor = 13,
    ClientTweetNotInterestedIn = 14,
    ClientTweetBlockAuthor = 15,
    ClientTweetMuteAuthor = 16,
    ClientTweetReport = 17,
}

// ── ContinuousActionName Enum ───────────────────────────────────────────────

/// Enumeration of continuous user actions (e.g., dwell time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum ContinuousActionName {
    DwellTime = 0,
}

// ── TweetInfo ───────────────────────────────────────────────────────────────

/// Information about a tweet candidate for scoring.
#[derive(Debug, Clone, Default)]
pub struct TweetInfo {
    pub tweet_id: u64,
    pub author_id: u64,
}

// ── PredictNextActionsResponse ──────────────────────────────────────────────

/// A candidate in the prediction response.
#[derive(Debug, Clone, Default)]
pub struct PredictionCandidate {
    pub tweet_id: u64,
}

/// Distribution of prediction probabilities for a single candidate.
#[derive(Debug, Clone, Default)]
pub struct CandidateDistribution {
    pub candidate: Option<PredictionCandidate>,
    pub top_log_probs: Vec<f32>,
    pub continuous_actions_values: Vec<f32>,
}

/// A set of candidate distributions for one prediction batch.
#[derive(Debug, Clone, Default)]
pub struct DistributionSet {
    pub candidate_distributions: Vec<CandidateDistribution>,
}

/// Response from the Phoenix prediction service.
#[derive(Debug, Clone, Default)]
pub struct PredictNextActionsResponse {
    pub distribution_sets: Vec<DistributionSet>,
}

// ── UserActionSequence ──────────────────────────────────────────────────────

/// Metadata about a user action sequence.
#[derive(Debug, Clone, Default)]
pub struct UserActionSequenceMeta {
    pub length: u64,
    pub first_sequence_time: u64,
    pub last_sequence_time: u64,
    pub last_modified_epoch_ms: u64,
    pub previous_kafka_publish_epoch_ms: u64,
}

/// An aggregated user action in the proto format.
#[derive(Debug, Clone, Default)]
pub struct AggregatedUserAction {
    pub tweet_id: u64,
    pub action_type: i32,
    pub count: u64,
    pub impressed_time_ms: u64,
}

/// A list of aggregated user actions.
#[derive(Debug, Clone, Default)]
pub struct AggregatedUserActionList {
    pub aggregated_user_actions: Vec<AggregatedUserAction>,
    pub aggregation_provider: String,
    pub aggregation_time_ms: u64,
}

/// Mask applied to a user action sequence.
#[derive(Debug, Clone, Default)]
pub struct Mask {
    pub mask_type: i32,
    pub mask: Vec<bool>,
}

/// Mask type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MaskType {
    NewEvent = 0,
    Existing = 1,
}

/// Container for user action sequence data (oneof field).
pub mod user_action_sequence_data_container {
    use super::*;

    #[derive(Debug, Clone)]
    pub enum Data {
        OrderedAggregatedUserActionsList(AggregatedUserActionList),
    }
}

/// Container wrapping the user action sequence data variant.
#[derive(Debug, Clone, Default)]
pub struct UserActionSequenceDataContainer {
    pub data: Option<user_action_sequence_data_container::Data>,
}

/// A user's recent action sequence used for scoring.
#[derive(Debug, Clone, Default)]
pub struct UserActionSequence {
    pub user_id: u64,
    pub metadata: Option<UserActionSequenceMeta>,
    pub user_actions_data: Option<UserActionSequenceDataContainer>,
    pub masks: Vec<Mask>,
}
