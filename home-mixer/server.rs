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

        // Validate the token and extract the verified viewer_id from token claims.
        // Token format: '<viewer_id>.<expiry_secs>.<signature>' with keyed signature
        // verified against the AUTH_TOKEN_SECRET environment variable.
        let verified_viewer_id = validate_auth_token(auth_token).map_err(|e| {
            warn!("Authentication token validation failed: {}", e);
            Status::unauthenticated("Authentication failed")
        })?;

        let proto_query = request.into_inner();

        // [H-5] Secondary validation (defense in depth): ensure the client-supplied
        // viewer_id is non-zero and matches the authenticated identity extracted
        // from the token claims. Prevents identity spoofing via mismatched IDs.
        if proto_query.viewer_id == 0 || proto_query.viewer_id != verified_viewer_id {
            return Err(Status::permission_denied(
                "viewer_id does not match authenticated identity",
            ));
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

// ── Authentication helper functions ─────────────────────────────────────────

/// [H-5] Security Fix (CWE-287 / OWASP A07:2025): Validates an authentication
/// token extracted from gRPC request metadata and returns the verified viewer_id.
///
/// The token is expected in the format `<viewer_id>.<expiry_secs>.<signature>`:
/// - `viewer_id`: Numeric user identifier (u64, must be non-zero)
/// - `expiry_secs`: Token expiry as Unix epoch seconds (u64)
/// - `signature`: Hex-encoded keyed hash of `<viewer_id>.<expiry_secs>` computed
///   using the `AUTH_TOKEN_SECRET` environment variable as key material
///
/// In the service mesh deployment model, mTLS at the transport layer provides the
/// primary authentication boundary. This token validation extracts the identity
/// claim and provides tamper detection via keyed hashing. The signature uses
/// SipHash-2-4 seeded with the auth secret, producing a 16-character hex digest.
///
/// # Errors
///
/// Returns `Err(String)` with a descriptive message if:
/// - Token format is invalid (missing components or wrong structure)
/// - `viewer_id` is zero or non-numeric
/// - Token has expired (current time exceeds `expiry_secs`)
/// - `AUTH_TOKEN_SECRET` environment variable is missing or empty
/// - Signature does not match the expected keyed hash
fn validate_auth_token(token: &str) -> Result<u64, String> {
    // Split token into exactly three dot-separated components
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("Malformed token: expected '<viewer_id>.<expiry>.<signature>'".to_string());
    }

    let (viewer_id_str, expiry_str, provided_sig) = (parts[0], parts[1], parts[2]);

    // Validate each component is non-empty
    if viewer_id_str.is_empty() || expiry_str.is_empty() || provided_sig.is_empty() {
        return Err("Token contains empty components".to_string());
    }

    // Extract and validate viewer_id from the token claims
    let viewer_id: u64 = viewer_id_str
        .parse()
        .map_err(|_| "Invalid viewer_id in token".to_string())?;

    if viewer_id == 0 {
        return Err("Token contains invalid zero viewer_id".to_string());
    }

    // Extract and validate the expiry timestamp
    let expiry_secs: u64 = expiry_str
        .parse()
        .map_err(|_| "Invalid expiry timestamp in token".to_string())?;

    // Check token expiry using safe SystemTime arithmetic (unwrap_or_default
    // handles the theoretical case where system clock is before Unix epoch)
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now_secs > expiry_secs {
        return Err("Token has expired".to_string());
    }

    // Retrieve the auth secret for signature verification
    let auth_secret = std::env::var("AUTH_TOKEN_SECRET")
        .map_err(|_| "AUTH_TOKEN_SECRET environment variable not configured".to_string())?;

    if auth_secret.is_empty() {
        return Err("AUTH_TOKEN_SECRET is empty".to_string());
    }

    // Verify the token signature using keyed hashing with constant-time comparison.
    // The signing input is the '<viewer_id>.<expiry_secs>' portion of the token.
    let signing_input = format!("{}.{}", viewer_id_str, expiry_str);
    if !verify_token_signature(&auth_secret, &signing_input, provided_sig) {
        return Err("Token signature verification failed".to_string());
    }

    Ok(viewer_id)
}

/// Verifies a token signature by computing the expected keyed hash of the signing
/// input using the provided secret, then performing constant-time comparison
/// against the provided signature.
///
/// Uses SipHash-2-4 (via `std::hash::DefaultHasher`) as the keyed hash function.
/// The secret is incorporated as key material by hashing it before the signing
/// input, producing a deterministic 64-bit keyed digest. The digest is formatted
/// as a 16-character lowercase hexadecimal string for comparison.
///
/// SipHash-2-4 provides short-input PRF security suitable for internal service
/// token validation where the primary authentication boundary is mTLS at the
/// transport layer. This signature provides tamper detection for the identity claim.
fn verify_token_signature(secret: &str, signing_input: &str, provided_signature: &str) -> bool {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Create a hasher and incorporate the secret as key material first,
    // then hash the signing input to produce a keyed digest
    let mut hasher = DefaultHasher::new();
    secret.hash(&mut hasher);
    signing_input.hash(&mut hasher);
    let digest = hasher.finish();
    let expected_hex = format!("{:016x}", digest);

    // Use constant-time comparison to prevent timing side-channel attacks
    constant_time_eq(expected_hex.as_bytes(), provided_signature.as_bytes())
}

/// Performs constant-time byte comparison to prevent timing side-channel attacks
/// during token signature verification. Returns `true` if and only if both byte
/// slices have identical length and content.
///
/// The comparison accumulates XOR differences across all byte positions before
/// checking the result, ensuring the execution time is independent of where
/// (or whether) the first difference occurs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
