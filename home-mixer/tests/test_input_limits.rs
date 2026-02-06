//! Integration tests for Fix M-6 (CWE-770 / OWASP A05:2025): Input size validation
//! for the Home Mixer gRPC endpoint.
//!
//! These tests verify that the `HomeMixerServer::get_scored_posts()` method rejects
//! requests containing oversized `seen_ids`, `served_ids`, or `bloom_filter_entries`
//! arrays with `Status::invalid_argument` before pipeline execution begins. This
//! prevents a CWE-770 (Allocation of Resources Without Limits or Throttling)
//! vulnerability where an attacker could cause excessive memory allocation and
//! processing time by sending unbounded input arrays in the gRPC request.
//!
//! **Security context:**
//! - **Fix:** M-6 — Input size validation at the gRPC server entry point
//! - **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
//! - **OWASP:** A05:2025 (Injection) — unbounded arrays as a resource exhaustion vector
//! - **Limits enforced:**
//!   - `MAX_SEEN_IDS = 10,000`
//!   - `MAX_SERVED_IDS = 10,000`
//!   - `MAX_BLOOM_FILTER_ENTRIES = 50,000`
//!
//! **Validation order in `get_scored_posts()`:**
//! 1. Semaphore-based concurrency check (M-5)
//! 2. Authentication token extraction and validation (H-5)
//! 3. `viewer_id` match against authenticated identity
//! 4. **Input size validation (M-6) — tested here**
//! 5. Pipeline execution
//!
//! Each test constructs a valid authentication token (to pass step 2) and sets up
//! the required `AUTH_TOKEN_SECRET` environment variable before exercising the
//! input validation layer.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;
use tonic::{Code, Request};
use xai_home_mixer::HomeMixerServer;
use xai_home_mixer_proto::scored_posts_service_server::ScoredPostsService;
use xai_home_mixer_proto::{ImpressionBloomFilterEntry, ScoredPostsQuery};

// ---------------------------------------------------------------------------
// Constants mirroring the limits defined in home-mixer/server.rs.
// These MUST stay in sync with the server-side constants for tests to be valid.
// ---------------------------------------------------------------------------

/// Maximum number of `seen_ids` entries allowed per request (mirrors server.rs).
const MAX_SEEN_IDS: usize = 10_000;

/// Maximum number of `served_ids` entries allowed per request (mirrors server.rs).
const MAX_SERVED_IDS: usize = 10_000;

/// Maximum number of `bloom_filter_entries` allowed per request (mirrors server.rs).
const MAX_BLOOM_FILTER_ENTRIES: usize = 50_000;

// ---------------------------------------------------------------------------
// Test authentication infrastructure
// ---------------------------------------------------------------------------

/// Shared secret used by all tests for auth token generation. Each test sets the
/// `AUTH_TOKEN_SECRET` environment variable to this value before calling the server.
const TEST_AUTH_SECRET: &str = "test-auth-secret-for-input-limit-tests";

/// A valid non-zero viewer ID used across all tests in this module.
const TEST_VIEWER_ID: i64 = 42;

/// Generates a valid authentication token that passes the H-5 auth validation in
/// `server.rs::validate_auth_token()`.
///
/// The token format is `<viewer_id>.<expiry_secs>.<signature>` where:
/// - `viewer_id` is the numeric user identifier (u64)
/// - `expiry_secs` is a Unix timestamp set 3600 seconds in the future
/// - `signature` is the SipHash-2-4 keyed hash of `"<viewer_id>.<expiry_secs>"`
///   using `TEST_AUTH_SECRET` as key material, formatted as 16-char lowercase hex
///
/// This replicates the signing logic in `server.rs::verify_token_signature()` to
/// produce tokens the server will accept.
fn generate_test_auth_token(viewer_id: u64) -> String {
    let expiry_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 3600; // Token valid for 1 hour from now

    let signing_input = format!("{}.{}", viewer_id, expiry_secs);

    // Replicate the SipHash-2-4 keyed hash from server.rs verify_token_signature()
    let mut hasher = DefaultHasher::new();
    TEST_AUTH_SECRET.hash(&mut hasher);
    signing_input.hash(&mut hasher);
    let digest = hasher.finish();
    let signature = format!("{:016x}", digest);

    format!("{}.{}.{}", viewer_id, expiry_secs, signature)
}

/// Configures the `AUTH_TOKEN_SECRET` environment variable required by the
/// server's token validation. Called at the start of each test to ensure the
/// auth layer accepts the test-generated tokens.
fn setup_test_env() {
    // All tests use the same secret value so concurrent test execution does not
    // cause env var conflicts.
    std::env::set_var("AUTH_TOKEN_SECRET", TEST_AUTH_SECRET);
}

/// Creates a `tonic::Request<ScoredPostsQuery>` pre-populated with a valid
/// `x-auth-token` metadata header matching the query's `viewer_id`.
///
/// This ensures every test request passes the H-5 authentication check (step 2)
/// before reaching the M-6 input validation check (step 4).
fn make_authenticated_request(query: ScoredPostsQuery) -> Request<ScoredPostsQuery> {
    let token = generate_test_auth_token(query.viewer_id as u64);
    let mut request = Request::new(query);
    request
        .metadata_mut()
        .insert("x-auth-token", token.parse().expect("valid ASCII auth token"));
    request
}

/// Constructs a base `ScoredPostsQuery` with a valid `viewer_id` and empty arrays.
/// Callers can override specific fields (e.g., `seen_ids`, `served_ids`) before
/// wrapping in an authenticated request.
fn make_base_query() -> ScoredPostsQuery {
    ScoredPostsQuery {
        viewer_id: TEST_VIEWER_ID,
        client_app_id: 1,
        country_code: "US".to_string(),
        language_code: "en".to_string(),
        seen_ids: Vec::new(),
        served_ids: Vec::new(),
        in_network_only: false,
        is_bottom_request: false,
        bloom_filter_entries: Vec::new(),
        auth_token: String::new(),
    }
}

// ===========================================================================
// Test 1: Oversized seen_ids are rejected with INVALID_ARGUMENT
// ===========================================================================

/// Validates Fix M-6 (CWE-770 / OWASP A05:2025): A request with `seen_ids`
/// containing more than `MAX_SEEN_IDS` (10,000) entries is rejected with
/// `Status::invalid_argument` before pipeline execution begins.
///
/// This is the primary validation for the CWE-770 input size limit on `seen_ids`.
#[tokio::test]
async fn test_oversized_seen_ids_rejected() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let mut query = make_base_query();
    // Construct an array one element beyond the allowed limit
    query.seen_ids = vec![0i64; MAX_SEEN_IDS + 1];

    let request = make_authenticated_request(query);
    let result = server.get_scored_posts(request).await;

    assert!(
        result.is_err(),
        "Request with {} seen_ids should be rejected",
        MAX_SEEN_IDS + 1
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::InvalidArgument,
        "Expected INVALID_ARGUMENT status code, got {:?}",
        status.code()
    );
    assert!(
        status.message().contains("seen_ids exceeds maximum"),
        "Error message should mention 'seen_ids exceeds maximum', got: '{}'",
        status.message()
    );
}

// ===========================================================================
// Test 2: Oversized served_ids are rejected with INVALID_ARGUMENT
// ===========================================================================

/// Validates Fix M-6 (CWE-770 / OWASP A05:2025): A request with `served_ids`
/// containing more than `MAX_SERVED_IDS` (10,000) entries is rejected with
/// `Status::invalid_argument`.
#[tokio::test]
async fn test_oversized_served_ids_rejected() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let mut query = make_base_query();
    // Construct an array one element beyond the allowed limit
    query.served_ids = vec![0i64; MAX_SERVED_IDS + 1];

    let request = make_authenticated_request(query);
    let result = server.get_scored_posts(request).await;

    assert!(
        result.is_err(),
        "Request with {} served_ids should be rejected",
        MAX_SERVED_IDS + 1
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::InvalidArgument,
        "Expected INVALID_ARGUMENT status code, got {:?}",
        status.code()
    );
    assert!(
        status.message().contains("served_ids exceeds maximum"),
        "Error message should mention 'served_ids exceeds maximum', got: '{}'",
        status.message()
    );
}

// ===========================================================================
// Test 3: Oversized bloom_filter_entries are rejected with INVALID_ARGUMENT
// ===========================================================================

/// Validates Fix M-6 (CWE-770 / OWASP A05:2025): A request with
/// `bloom_filter_entries` containing more than `MAX_BLOOM_FILTER_ENTRIES` (50,000)
/// entries is rejected with `Status::invalid_argument`.
#[tokio::test]
async fn test_oversized_bloom_filter_entries_rejected() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let mut query = make_base_query();
    // Construct an array one element beyond the allowed limit
    query.bloom_filter_entries =
        vec![ImpressionBloomFilterEntry::default(); MAX_BLOOM_FILTER_ENTRIES + 1];

    let request = make_authenticated_request(query);
    let result = server.get_scored_posts(request).await;

    assert!(
        result.is_err(),
        "Request with {} bloom_filter_entries should be rejected",
        MAX_BLOOM_FILTER_ENTRIES + 1
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::InvalidArgument,
        "Expected INVALID_ARGUMENT status code, got {:?}",
        status.code()
    );
    assert!(
        status
            .message()
            .contains("bloom_filter_entries exceeds maximum"),
        "Error message should mention 'bloom_filter_entries exceeds maximum', got: '{}'",
        status.message()
    );
}

// ===========================================================================
// Test 4: seen_ids at exact limit are accepted (boundary test)
// ===========================================================================

/// Validates Fix M-6 boundary condition: A request with exactly `MAX_SEEN_IDS`
/// (10,000) entries in `seen_ids` passes input validation. The request may fail
/// later in the pipeline for other reasons, but it must NOT be rejected with
/// `Status::invalid_argument` for `seen_ids` size.
#[tokio::test]
async fn test_seen_ids_at_exact_limit_accepted() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let mut query = make_base_query();
    query.seen_ids = vec![0i64; MAX_SEEN_IDS]; // Exactly at the limit

    let request = make_authenticated_request(query);
    let result = server.get_scored_posts(request).await;

    // The request should not be rejected for input size violation. It may fail
    // for other pipeline-related reasons, but the error must not be about
    // seen_ids exceeding the maximum.
    match result {
        Ok(_) => {} // Input validation passed and pipeline succeeded
        Err(status) => {
            assert_ne!(
                status.code(),
                Code::InvalidArgument,
                "Request with exactly {} seen_ids should NOT be rejected for input size; \
                 got INVALID_ARGUMENT: '{}'",
                MAX_SEEN_IDS,
                status.message()
            );
            // Confirm the error is not related to seen_ids size validation
            assert!(
                !status.message().contains("seen_ids exceeds maximum"),
                "At-limit seen_ids should not trigger size validation error, got: '{}'",
                status.message()
            );
        }
    }
}

// ===========================================================================
// Test 5: served_ids at exact limit are accepted (boundary test)
// ===========================================================================

/// Validates Fix M-6 boundary condition: A request with exactly `MAX_SERVED_IDS`
/// (10,000) entries in `served_ids` passes input validation.
#[tokio::test]
async fn test_served_ids_at_exact_limit_accepted() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let mut query = make_base_query();
    query.served_ids = vec![0i64; MAX_SERVED_IDS]; // Exactly at the limit

    let request = make_authenticated_request(query);
    let result = server.get_scored_posts(request).await;

    match result {
        Ok(_) => {} // Input validation passed and pipeline succeeded
        Err(status) => {
            assert_ne!(
                status.code(),
                Code::InvalidArgument,
                "Request with exactly {} served_ids should NOT be rejected for input size; \
                 got INVALID_ARGUMENT: '{}'",
                MAX_SERVED_IDS,
                status.message()
            );
            assert!(
                !status.message().contains("served_ids exceeds maximum"),
                "At-limit served_ids should not trigger size validation error, got: '{}'",
                status.message()
            );
        }
    }
}

// ===========================================================================
// Test 6: bloom_filter_entries at exact limit are accepted (boundary test)
// ===========================================================================

/// Validates Fix M-6 boundary condition: A request with exactly
/// `MAX_BLOOM_FILTER_ENTRIES` (50,000) entries in `bloom_filter_entries` passes
/// input validation.
#[tokio::test]
async fn test_bloom_filter_entries_at_exact_limit_accepted() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let mut query = make_base_query();
    query.bloom_filter_entries =
        vec![ImpressionBloomFilterEntry::default(); MAX_BLOOM_FILTER_ENTRIES]; // Exactly at the limit

    let request = make_authenticated_request(query);
    let result = server.get_scored_posts(request).await;

    match result {
        Ok(_) => {} // Input validation passed and pipeline succeeded
        Err(status) => {
            assert_ne!(
                status.code(),
                Code::InvalidArgument,
                "Request with exactly {} bloom_filter_entries should NOT be rejected for \
                 input size; got INVALID_ARGUMENT: '{}'",
                MAX_BLOOM_FILTER_ENTRIES,
                status.message()
            );
            assert!(
                !status
                    .message()
                    .contains("bloom_filter_entries exceeds maximum"),
                "At-limit bloom_filter_entries should not trigger size validation error, got: '{}'",
                status.message()
            );
        }
    }
}

// ===========================================================================
// Test 7: Empty arrays are accepted (zero-size boundary test)
// ===========================================================================

/// Validates Fix M-6 zero-boundary condition: A request with empty `seen_ids`,
/// `served_ids`, and `bloom_filter_entries` arrays passes input validation.
/// Empty arrays are well within the limits and must not trigger rejection.
#[tokio::test]
async fn test_empty_arrays_accepted() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    // All arrays empty by default from make_base_query()
    let query = make_base_query();
    let request = make_authenticated_request(query);
    let result = server.get_scored_posts(request).await;

    match result {
        Ok(_) => {} // Input validation passed and pipeline succeeded
        Err(status) => {
            // Verify no input size validation error — the request may fail for
            // pipeline reasons but must not be rejected for array sizes
            assert_ne!(
                status.code(),
                Code::InvalidArgument,
                "Request with empty arrays should NOT be rejected for input size; \
                 got INVALID_ARGUMENT: '{}'",
                status.message()
            );
            assert!(
                !status.message().contains("exceeds maximum"),
                "Empty arrays should not trigger any 'exceeds maximum' validation error, got: '{}'",
                status.message()
            );
        }
    }
}

// ===========================================================================
// Test 8: Multiple oversized arrays — first violation (seen_ids) is reported
// ===========================================================================

/// Validates Fix M-6 sequential validation order: When BOTH `seen_ids` and
/// `served_ids` exceed their respective limits, the error message references
/// `seen_ids` because it is validated first in the sequential check order
/// within `get_scored_posts()`.
///
/// This confirms the server checks arrays in the expected order:
/// `seen_ids` → `served_ids` → `bloom_filter_entries`.
#[tokio::test]
async fn test_multiple_oversized_arrays_first_checked() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let mut query = make_base_query();
    // Both arrays exceed their respective limits
    query.seen_ids = vec![0i64; MAX_SEEN_IDS + 1];
    query.served_ids = vec![0i64; MAX_SERVED_IDS + 1];

    let request = make_authenticated_request(query);
    let result = server.get_scored_posts(request).await;

    assert!(
        result.is_err(),
        "Request with multiple oversized arrays should be rejected"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::InvalidArgument,
        "Expected INVALID_ARGUMENT status code, got {:?}",
        status.code()
    );
    // seen_ids is validated first in server.rs, so its error message should appear
    assert!(
        status.message().contains("seen_ids exceeds maximum"),
        "Error message should reference 'seen_ids' (checked first) when both arrays \
         exceed limits, got: '{}'",
        status.message()
    );
}

// ===========================================================================
// Test 9: Very large array (100,000 entries) — rapid rejection without timeout
// ===========================================================================

/// Validates Fix M-6 with a very large array (100,000 entries in `seen_ids`) as
/// specified in Section 0.8.1: "Send a GetScoredPosts request with 100,000+
/// entries in seen_ids and verify the request is rejected before pipeline
/// execution."
///
/// This test verifies that:
/// 1. The oversized array is rejected with `Status::invalid_argument`
/// 2. Rejection occurs rapidly (well under 1 second) confirming the check happens
///    at the input validation layer BEFORE pipeline execution
/// 3. No memory exhaustion or timeout occurs from the large array size
///
/// CWE-770 attack scenario: An attacker floods the endpoint with 100,000+ element
/// arrays attempting to exhaust server memory and processing capacity.
#[tokio::test]
async fn test_very_large_array_100k_entries_rejected() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let mut query = make_base_query();
    // 100,000 entries — 10x the limit, matching the Section 0.8.1 test scenario
    query.seen_ids = vec![0i64; 100_000];

    let request = make_authenticated_request(query);

    // Measure rejection time to confirm it happens at the validation layer
    // (before pipeline execution) — should be sub-millisecond
    let start = Instant::now();
    let result = server.get_scored_posts(request).await;
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "Request with 100,000 seen_ids must be rejected"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::InvalidArgument,
        "Expected INVALID_ARGUMENT status code for 100k entries, got {:?}",
        status.code()
    );
    assert!(
        status.message().contains("seen_ids exceeds maximum"),
        "Error message should mention 'seen_ids exceeds maximum', got: '{}'",
        status.message()
    );

    // Input validation should reject the request almost instantly — well under
    // 1 second. If pipeline execution were reached, response time would be
    // significantly longer due to network calls and processing.
    assert!(
        elapsed.as_secs() < 1,
        "Rejection of 100k-entry array took {:?} — expected sub-second rejection at \
         the input validation layer before pipeline execution",
        elapsed
    );
}
