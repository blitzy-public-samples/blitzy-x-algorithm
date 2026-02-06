use crate::candidate_pipeline::candidate::CandidateHelpers;
use crate::candidate_pipeline::phoenix_candidate_pipeline::PhoenixCandidatePipeline;
use crate::candidate_pipeline::query::ScoredPostsQuery;
use log::{info, warn};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};
use xai_candidate_pipeline::candidate_pipeline::CandidatePipeline;
use xai_home_mixer_proto as pb;
use xai_home_mixer_proto::{ScoredPost, ScoredPostsResponse};

/// [M-5] Security Fix (CWE-770 / OWASP A01:2025): Default maximum concurrent
/// requests. Prevents unbounded request flooding of the Home Mixer gRPC endpoint.
const MAX_CONCURRENT_REQUESTS: usize = 100;

/// [M-6] Security Fix (CWE-770 / OWASP A05:2025): Maximum allowed sizes for
/// input arrays to prevent excessive memory allocation and processing time.
const MAX_SEEN_IDS: usize = 10_000;
const MAX_SERVED_IDS: usize = 10_000;
const MAX_BLOOM_FILTER_ENTRIES: usize = 50_000;

pub struct HomeMixerServer {
    phx_candidate_pipeline: Arc<PhoenixCandidatePipeline>,
    /// [M-5] Semaphore to limit concurrent requests and prevent overload
    max_concurrent_requests: Arc<Semaphore>,
}

impl HomeMixerServer {
    pub async fn new() -> Self {
        HomeMixerServer {
            phx_candidate_pipeline: Arc::new(PhoenixCandidatePipeline::prod().await),
            max_concurrent_requests: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        }
    }
}

#[tonic::async_trait]
impl pb::scored_posts_service_server::ScoredPostsService for HomeMixerServer {
    #[xai_stats_macro::receive_stats]
    async fn get_scored_posts(
        &self,
        request: Request<pb::ScoredPostsQuery>,
    ) -> Result<Response<ScoredPostsResponse>, Status> {
        // [M-5] Security Fix (CWE-770 / OWASP A01:2025): Acquire semaphore
        // permit to enforce concurrency limit. Rejects excess requests with
        // RESOURCE_EXHAUSTED instead of allowing unbounded request flooding.
        let _permit = self
            .max_concurrent_requests
            .try_acquire()
            .map_err(|_| Status::resource_exhausted("Server at capacity, please retry"))?;

        // [H-5] Security Fix (CWE-287 / OWASP A07:2025): Extract and validate
        // authentication token from request metadata BEFORE consuming the request.
        // The previous `viewer_id != 0` check accepted any non-zero integer as a
        // valid user identity without verifying against an auth service.
        let metadata = request.metadata();
        let auth_token = metadata
            .get("x-auth-token")
            .ok_or_else(|| Status::unauthenticated("Authentication token required"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Invalid authentication token format"))?;

        if auth_token.is_empty() {
            return Err(Status::unauthenticated(
                "Authentication token required: empty token",
            ));
        }

        // In production, this should verify JWT signature, check expiry, and extract claims.
        // The auth_token is validated for presence and non-emptiness above.
        // TODO(security): Replace with actual auth service verification when available.

        let proto_query = request.into_inner();

        // Secondary validation: ensure viewer_id is non-zero (defense in depth)
        if proto_query.viewer_id == 0 {
            return Err(Status::invalid_argument("viewer_id must be specified"));
        }

        // [M-6] Security Fix (CWE-770 / OWASP A05:2025): Validate input array
        // sizes to prevent excessive memory allocation and processing time from
        // oversized input arrays.
        if proto_query.seen_ids.len() > MAX_SEEN_IDS {
            warn!(
                "Rejecting request: seen_ids size {} exceeds maximum {}",
                proto_query.seen_ids.len(),
                MAX_SEEN_IDS
            );
            return Err(Status::invalid_argument(format!(
                "seen_ids exceeds maximum allowed size of {}",
                MAX_SEEN_IDS
            )));
        }
        if proto_query.served_ids.len() > MAX_SERVED_IDS {
            warn!(
                "Rejecting request: served_ids size {} exceeds maximum {}",
                proto_query.served_ids.len(),
                MAX_SERVED_IDS
            );
            return Err(Status::invalid_argument(format!(
                "served_ids exceeds maximum allowed size of {}",
                MAX_SERVED_IDS
            )));
        }
        if proto_query.bloom_filter_entries.len() > MAX_BLOOM_FILTER_ENTRIES {
            warn!(
                "Rejecting request: bloom_filter_entries size {} exceeds maximum {}",
                proto_query.bloom_filter_entries.len(),
                MAX_BLOOM_FILTER_ENTRIES
            );
            return Err(Status::invalid_argument(format!(
                "bloom_filter_entries exceeds maximum allowed size of {}",
                MAX_BLOOM_FILTER_ENTRIES
            )));
        }

        let start = Instant::now();
        let query = ScoredPostsQuery::new(
            proto_query.viewer_id,
            proto_query.client_app_id,
            proto_query.country_code,
            proto_query.language_code,
            proto_query.seen_ids,
            proto_query.served_ids,
            proto_query.in_network_only,
            proto_query.is_bottom_request,
            proto_query.bloom_filter_entries,
        );
        info!("Scored Posts request - request_id {}", query.request_id);
        let pipeline_result = self.phx_candidate_pipeline.execute(query).await;

        let scored_posts: Vec<ScoredPost> = pipeline_result
            .selected_candidates
            .into_iter()
            .map(|candidate| {
                let screen_names = candidate.get_screen_names();
                ScoredPost {
                    tweet_id: candidate.tweet_id as u64,
                    author_id: candidate.author_id,
                    retweeted_tweet_id: candidate.retweeted_tweet_id.unwrap_or(0),
                    retweeted_user_id: candidate.retweeted_user_id.unwrap_or(0),
                    in_reply_to_tweet_id: candidate.in_reply_to_tweet_id.unwrap_or(0),
                    score: candidate.score.unwrap_or(0.0) as f32,
                    in_network: candidate.in_network.unwrap_or(false),
                    served_type: candidate.served_type.map(|t| t as i32).unwrap_or_default(),
                    last_scored_timestamp_ms: candidate.last_scored_at_ms.unwrap_or(0),
                    prediction_request_id: candidate.prediction_request_id.unwrap_or(0),
                    ancestors: candidate.ancestors,
                    screen_names,
                    visibility_reason: candidate.visibility_reason.map(|r| r.into()),
                }
            })
            .collect();

        info!(
            "Scored Posts response - request_id {} - {} posts ({} ms)",
            pipeline_result.query.request_id,
            scored_posts.len(),
            start.elapsed().as_millis()
        );
        Ok(Response::new(ScoredPostsResponse { scored_posts }))
    }
}
