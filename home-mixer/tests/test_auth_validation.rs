//! Security integration tests for Home Mixer authentication validation.
//!
//! **Validates:** Fix H-5 (CWE-287 / OWASP A07:2025) — Replacement of the weak
//! `viewer_id != 0` authentication check in `HomeMixerServer::get_scored_posts()`
//! with proper auth token validation using keyed signature verification.
//!
//! # Background
//!
//! Prior to Fix H-5, the Home Mixer gRPC endpoint accepted **any non-zero integer**
//! as a valid `viewer_id` without verifying the caller's identity against an
//! authentication service (CWE-287: Improper Authentication). The fix introduces
//! mandatory extraction and validation of an `x-auth-token` gRPC metadata header
//! before the request body is consumed.
//!
//! The token format is `<viewer_id>.<expiry_secs>.<signature>` where:
//! - `viewer_id`: Numeric user identifier (u64, non-zero)
//! - `expiry_secs`: Token expiry as Unix epoch seconds
//! - `signature`: SipHash-2-4 keyed hash of `"<viewer_id>.<expiry_secs>"` using
//!   the `AUTH_TOKEN_SECRET` environment variable as key material, formatted as a
//!   16-character lowercase hexadecimal string
//!
//! The server performs the following validation steps in order:
//! 1. Semaphore-based concurrency check (Fix M-5)
//! 2. **Auth token extraction from `x-auth-token` metadata (Fix H-5)**
//! 3. **Auth token format, expiry, and signature validation (Fix H-5)**
//! 4. **`viewer_id` match against authenticated identity (Fix H-5)**
//! 5. Input size validation (Fix M-6)
//! 6. Pipeline execution
//!
//! # Test Strategy
//!
//! Tests use `HomeMixerServer::new().await` to construct the actual server instance,
//! matching the established pattern in `test_input_limits.rs`. Authentication
//! failures (tests 1–3, 5–7) are rejected before pipeline execution, so the
//! `PhoenixCandidatePipeline` is never invoked for those cases. For the valid-token
//! success test (test 4), the pipeline is invoked and may produce a business-logic
//! error; the test asserts only that the gRPC status code is NOT `Unauthenticated`
//! or `PermissionDenied`, confirming that authentication passed.
//!
//! A compile-time trait bound assertion confirms that `HomeMixerServer` implements
//! the `ScoredPostsService` trait, ensuring the production struct exposes the same
//! gRPC entry point tested here.
//!
//! # References
//!
//! - CWE-287: Improper Authentication
//! - OWASP A07:2025: Identification and Authentication Failures
//! - Fix H-5 in Agent Action Plan Section 0.5.1
//! - Server implementation: `home-mixer/server.rs` lines 54–88

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tonic::{Code, Request, Response};
use xai_home_mixer::HomeMixerServer;
use xai_home_mixer_proto::scored_posts_service_server::ScoredPostsService;
use xai_home_mixer_proto::{ScoredPostsQuery, ScoredPostsResponse};

// ── Compile-Time Validation ─────────────────────────────────────────────────

/// Compile-time assertion that `HomeMixerServer` implements the
/// `ScoredPostsService` gRPC trait. This guarantees that the production server
/// struct exposes `get_scored_posts` — the method where Fix H-5 authentication
/// is enforced. If `HomeMixerServer` no longer implements the trait (e.g., due
/// to a refactor), this function will cause a compile error in the test crate.
#[allow(dead_code)]
fn assert_home_mixer_server_implements_scored_posts_service() {
    fn requires_service<T: ScoredPostsService>() {}
    requires_service::<HomeMixerServer>();
}

// ── Test Infrastructure ─────────────────────────────────────────────────────

/// Shared secret used by all tests for auth token generation. Each test sets the
/// `AUTH_TOKEN_SECRET` environment variable to this value before calling the server.
/// All tests in this module use the same secret to avoid env var races when tests
/// run concurrently under the Tokio test runtime.
const TEST_AUTH_SECRET: &str = "test-auth-secret-for-h5-validation";

/// A valid non-zero viewer ID used across most tests in this module.
const TEST_VIEWER_ID: i64 = 99001;

/// Secondary viewer ID used in the viewer_id mismatch test (test 6).
const MISMATCHED_VIEWER_ID: i64 = 99002;

/// Configures the `AUTH_TOKEN_SECRET` environment variable required by the
/// server's `validate_auth_token()` function. Called at the start of each test
/// to ensure the auth layer can verify test-generated tokens.
fn setup_test_env() {
    std::env::set_var("AUTH_TOKEN_SECRET", TEST_AUTH_SECRET);
}

/// Generates a valid authentication token that passes the H-5 auth validation
/// in `server.rs::validate_auth_token()`.
///
/// The token format is `<viewer_id>.<expiry_secs>.<signature>` where:
/// - `viewer_id` is the numeric user identifier (u64)
/// - `expiry_secs` is a Unix timestamp set 3600 seconds (1 hour) in the future
/// - `signature` is the SipHash-2-4 keyed hash of `"<viewer_id>.<expiry_secs>"`
///   using `TEST_AUTH_SECRET` as key material, formatted as 16-char lowercase hex
///
/// This replicates the exact signing logic in `server.rs::verify_token_signature()`
/// to produce tokens the server will accept.
fn generate_test_auth_token(viewer_id: u64) -> String {
    let expiry_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 3600; // Token valid for 1 hour from now

    let signing_input = format!("{}.{}", viewer_id, expiry_secs);

    // Replicate the SipHash-2-4 keyed hash from server.rs verify_token_signature():
    //   let mut hasher = DefaultHasher::new();
    //   secret.hash(&mut hasher);
    //   signing_input.hash(&mut hasher);
    //   let digest = hasher.finish();
    //   let expected_hex = format!("{:016x}", digest);
    let mut hasher = DefaultHasher::new();
    TEST_AUTH_SECRET.hash(&mut hasher);
    signing_input.hash(&mut hasher);
    let digest = hasher.finish();
    let signature = format!("{:016x}", digest);

    format!("{}.{}.{}", viewer_id, expiry_secs, signature)
}

/// Generates an expired authentication token for negative testing. The token
/// format and signature are valid, but the expiry timestamp is set 3600 seconds
/// (1 hour) in the past, causing `validate_auth_token()` to reject it with
/// "Token has expired".
fn generate_expired_auth_token(viewer_id: u64) -> String {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Set expiry to 1 hour in the past (guaranteed expired)
    let expiry_secs = now_secs.saturating_sub(3600);

    let signing_input = format!("{}.{}", viewer_id, expiry_secs);

    let mut hasher = DefaultHasher::new();
    TEST_AUTH_SECRET.hash(&mut hasher);
    signing_input.hash(&mut hasher);
    let digest = hasher.finish();
    let signature = format!("{:016x}", digest);

    format!("{}.{}.{}", viewer_id, expiry_secs, signature)
}

/// Constructs a base `ScoredPostsQuery` with the given `viewer_id` and empty
/// arrays. Callers can override specific fields before wrapping in a request.
fn make_base_query(viewer_id: i64) -> ScoredPostsQuery {
    ScoredPostsQuery {
        viewer_id,
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

/// Creates a `tonic::Request<ScoredPostsQuery>` with the specified auth token
/// injected into the `x-auth-token` gRPC metadata header.
fn make_request_with_token(
    query: ScoredPostsQuery,
    token: &str,
) -> Request<ScoredPostsQuery> {
    let mut request = Request::new(query);
    request
        .metadata_mut()
        .insert(
            "x-auth-token",
            token.parse().expect("valid ASCII auth token"),
        );
    request
}

/// Creates a `tonic::Request<ScoredPostsQuery>` WITHOUT any `x-auth-token`
/// metadata header. Used for testing that unauthenticated requests are rejected.
fn make_request_without_token(query: ScoredPostsQuery) -> Request<ScoredPostsQuery> {
    Request::new(query)
}

/// List of substrings that should NEVER appear in authentication error messages.
/// These represent internal implementation details whose exposure constitutes
/// CWE-209 (Generation of Error Message Containing Sensitive Information).
const FORBIDDEN_ERROR_SUBSTRINGS: &[&str] = &[
    "PhoenixCandidatePipeline",
    "phx_candidate_pipeline",
    "kafka",
    "Kafka",
    "postgres",
    "Postgres",
    "redis",
    "Redis",
    "internal server",
    "stack trace",
    "backtrace",
    "panicked",
    "thread",
    ".rs:",
    "line ",
    "src/",
    "home-mixer/",
    "thunder/",
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "http://",
    "https://",
    "grpc://",
    "AUTH_TOKEN_SECRET",
    "SipHash",
    "DefaultHasher",
    "env::var",
    "UNIX_EPOCH",
];

// ===========================================================================
// Test 1: Request without auth token is rejected (primary H-5 regression test)
// ===========================================================================

/// Validates Fix H-5 (CWE-287 / OWASP A07:2025): A gRPC request with a valid
/// `viewer_id` but NO `x-auth-token` metadata header is rejected with
/// `Status::unauthenticated()`.
///
/// **This is the primary regression test for H-5.** Prior to the fix, any
/// non-zero `viewer_id` was accepted without token verification. After the fix,
/// the server extracts `x-auth-token` from metadata first and rejects requests
/// that lack the header entirely.
///
/// **Attack vector prevented:** An attacker submitting a `GetScoredPosts` request
/// with an arbitrary `viewer_id` (e.g., `viewer_id=12345`) but no authentication
/// credential, gaining access to another user's personalized feed.
#[tokio::test]
async fn test_request_without_auth_token_is_rejected() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    // Construct a query with a valid non-zero viewer_id but no auth token
    let query = make_base_query(TEST_VIEWER_ID);
    let request = make_request_without_token(query);

    let result = server.get_scored_posts(request).await;

    // The server must reject this request with UNAUTHENTICATED status
    assert!(
        result.is_err(),
        "Expected UNAUTHENTICATED error for request without auth token, got Ok"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::Unauthenticated,
        "Expected Code::Unauthenticated, got {:?} with message: {}",
        status.code(),
        status.message()
    );

    // Verify the error message indicates the token is required
    assert!(
        status.message().contains("Authentication token required"),
        "Error message should indicate token is required, got: {}",
        status.message()
    );
}

// ===========================================================================
// Test 2: Request with empty auth token is rejected
// ===========================================================================

/// Validates Fix H-5 (CWE-287): A request with `x-auth-token` metadata header
/// set to an empty string is rejected with `Status::unauthenticated()`.
///
/// This tests a distinct code path from test 1: the header IS present (so
/// `metadata.get("x-auth-token")` returns `Some`), but the value is empty.
/// The server has an explicit empty-string check after extracting the token
/// to prevent bypassing validation with a present-but-blank header.
///
/// **Attack vector prevented:** An attacker setting `x-auth-token: ""` to
/// bypass a naive "header present" check without providing actual credentials.
#[tokio::test]
async fn test_request_with_empty_auth_token_is_rejected() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let query = make_base_query(TEST_VIEWER_ID);
    let request = make_request_with_token(query, "");

    let result = server.get_scored_posts(request).await;

    assert!(
        result.is_err(),
        "Expected UNAUTHENTICATED error for empty auth token, got Ok"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::Unauthenticated,
        "Expected Code::Unauthenticated for empty token, got {:?} with message: {}",
        status.code(),
        status.message()
    );

    // The server checks for empty tokens explicitly after extraction
    assert!(
        status.message().contains("Authentication token required")
            || status.message().contains("empty token"),
        "Error message should indicate empty/missing token, got: {}",
        status.message()
    );
}

// ===========================================================================
// Test 3: Request with invalid/malformed auth token is rejected
// ===========================================================================

/// Validates Fix H-5 (CWE-287): A request with a malformed `x-auth-token`
/// (not matching the `<viewer_id>.<expiry>.<signature>` format) is rejected
/// with `Status::unauthenticated()`.
///
/// This tests that the server doesn't merely check for token *presence* but
/// actually *validates* the token format, components, and signature. The
/// malformed token "invalid-token-12345" contains no dot separators, so
/// `validate_auth_token()` returns an error at the format check stage.
///
/// **Attack vector prevented:** An attacker sending an arbitrary string as the
/// auth token, hoping to bypass validation that only checks for header presence.
#[tokio::test]
async fn test_request_with_invalid_auth_token_is_rejected() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let query = make_base_query(TEST_VIEWER_ID);
    let request = make_request_with_token(query, "invalid-token-12345");

    let result = server.get_scored_posts(request).await;

    assert!(
        result.is_err(),
        "Expected UNAUTHENTICATED error for malformed auth token, got Ok"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::Unauthenticated,
        "Expected Code::Unauthenticated for malformed token, got {:?} with message: {}",
        status.code(),
        status.message()
    );

    // The validate_auth_token error is wrapped with a generic "Authentication failed"
    assert!(
        status.message().contains("Authentication failed"),
        "Error message should indicate authentication failure, got: {}",
        status.message()
    );
}

// ===========================================================================
// Test 3b: Request with wrong-signature auth token is rejected
// ===========================================================================

/// Validates Fix H-5 (CWE-287): A request with a structurally valid token
/// (correct format with three dot-separated parts and valid viewer_id/expiry)
/// but an incorrect signature is rejected with `Status::unauthenticated()`.
///
/// This is a more sophisticated attack than test 3: the attacker crafts a
/// token that passes format validation but fails signature verification.
/// The constant-time comparison in `verify_token_signature()` detects the
/// forged signature.
///
/// **Attack vector prevented:** An attacker guessing or brute-forcing the token
/// format and crafting a token with a plausible structure but invalid signature.
#[tokio::test]
async fn test_request_with_wrong_signature_is_rejected() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    // Craft a token with valid structure but forged signature
    let expiry_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 3600;
    let forged_token = format!("{}.{}.0000000000000000", TEST_VIEWER_ID, expiry_secs);

    let query = make_base_query(TEST_VIEWER_ID);
    let request = make_request_with_token(query, &forged_token);

    let result = server.get_scored_posts(request).await;

    assert!(
        result.is_err(),
        "Expected UNAUTHENTICATED error for forged-signature token, got Ok"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::Unauthenticated,
        "Expected Code::Unauthenticated for forged signature, got {:?} with message: {}",
        status.code(),
        status.message()
    );

    assert!(
        status.message().contains("Authentication failed"),
        "Error message should indicate authentication failure, got: {}",
        status.message()
    );
}

// ===========================================================================
// Test 3c: Request with expired auth token is rejected
// ===========================================================================

/// Validates Fix H-5 (CWE-287): A request with a correctly signed but expired
/// token (expiry timestamp in the past) is rejected with
/// `Status::unauthenticated()`.
///
/// This verifies that the server checks the token's temporal validity and
/// does not accept stale/replayed tokens. The token is signed correctly with
/// the proper secret but its `expiry_secs` is set 1 hour in the past.
///
/// **Attack vector prevented:** Token replay attacks where a captured token
/// is reused after its intended validity window has passed.
#[tokio::test]
async fn test_request_with_expired_auth_token_is_rejected() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let expired_token = generate_expired_auth_token(TEST_VIEWER_ID as u64);

    let query = make_base_query(TEST_VIEWER_ID);
    let request = make_request_with_token(query, &expired_token);

    let result = server.get_scored_posts(request).await;

    assert!(
        result.is_err(),
        "Expected UNAUTHENTICATED error for expired auth token, got Ok"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::Unauthenticated,
        "Expected Code::Unauthenticated for expired token, got {:?} with message: {}",
        status.code(),
        status.message()
    );

    assert!(
        status.message().contains("Authentication failed"),
        "Error message should indicate authentication failure, got: {}",
        status.message()
    );
}

// ===========================================================================
// Test 4: Request with valid auth token succeeds (passes authentication)
// ===========================================================================

/// Validates Fix H-5 (CWE-287): A request with a properly formatted, non-expired,
/// correctly signed auth token AND a matching `viewer_id` proceeds past the
/// authentication layer.
///
/// The test verifies that the gRPC response status code is **NOT**
/// `Code::Unauthenticated` or `Code::PermissionDenied`. The request may
/// produce a pipeline/business-logic error (e.g., if downstream services are
/// unavailable in the test environment), but authentication itself must succeed.
///
/// **Validation criteria:** The server accepts the token, extracts the verified
/// `viewer_id`, confirms it matches `proto_query.viewer_id`, and proceeds to
/// input validation and pipeline execution. Any non-auth error confirms
/// authentication passed.
#[tokio::test]
async fn test_request_with_valid_auth_token_succeeds() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    let valid_token = generate_test_auth_token(TEST_VIEWER_ID as u64);

    let query = make_base_query(TEST_VIEWER_ID);
    let request = make_request_with_token(query, &valid_token);

    let result: Result<Response<ScoredPostsResponse>, tonic::Status> =
        server.get_scored_posts(request).await;

    match result {
        Ok(response) => {
            // Authentication passed and pipeline execution succeeded — ideal outcome.
            // The response itself is not validated here; this test only verifies
            // that the auth layer does not reject valid credentials.
            // Verify the response wrapper is structurally sound.
            let _scored_response: &ScoredPostsResponse = response.get_ref();
        }
        Err(status) => {
            // If there's an error, it MUST NOT be an authentication or
            // permission error. Pipeline/business-logic errors (Internal,
            // Unavailable, etc.) are acceptable and expected in test environments
            // where backend services may not be running.
            assert_ne!(
                status.code(),
                Code::Unauthenticated,
                "Valid auth token should not produce UNAUTHENTICATED error, \
                 but got: {}",
                status.message()
            );
            assert_ne!(
                status.code(),
                Code::PermissionDenied,
                "Valid auth token with matching viewer_id should not produce \
                 PERMISSION_DENIED error, but got: {}",
                status.message()
            );
        }
    }
}

// ===========================================================================
// Test 5: viewer_id = 0 still rejected with valid token
// ===========================================================================

/// Validates Fix H-5 (CWE-287): A request with `viewer_id = 0` is rejected
/// even when accompanied by a valid auth token for a different (non-zero) user.
///
/// The server's secondary validation (defense in depth) checks:
///   `if proto_query.viewer_id == 0 || proto_query.viewer_id != verified_viewer_id as i64`
///
/// When `proto_query.viewer_id = 0` and the token contains a non-zero viewer_id,
/// both conditions trigger: `viewer_id == 0` is true, AND `0 != verified_viewer_id`
/// is true. The result is `Status::permission_denied()`.
///
/// **Attack vector prevented:** An attacker sending `viewer_id = 0` to access a
/// system/admin account or bypass viewer-specific filtering.
#[tokio::test]
async fn test_viewer_id_zero_still_rejected_with_valid_token() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    // Generate a valid token for a non-zero viewer_id, but set the query's
    // viewer_id to 0. The token validates successfully (for the non-zero ID),
    // but the secondary check rejects the zero viewer_id with PERMISSION_DENIED.
    let token_viewer_id: u64 = 55555;
    let valid_token = generate_test_auth_token(token_viewer_id);

    let query = make_base_query(0); // viewer_id = 0
    let request = make_request_with_token(query, &valid_token);

    let result = server.get_scored_posts(request).await;

    assert!(
        result.is_err(),
        "Expected rejection for viewer_id = 0, got Ok"
    );

    let status = result.unwrap_err();

    // The server rejects this with PERMISSION_DENIED because the viewer_id
    // in the query (0) does not match the authenticated identity from the token.
    assert_eq!(
        status.code(),
        Code::PermissionDenied,
        "Expected Code::PermissionDenied for viewer_id=0, got {:?} with message: {}",
        status.code(),
        status.message()
    );

    assert!(
        status
            .message()
            .contains("viewer_id does not match authenticated identity"),
        "Error message should indicate viewer_id mismatch, got: {}",
        status.message()
    );
}

// ===========================================================================
// Test 6: viewer_id mismatch with token claims is rejected
// ===========================================================================

/// Validates Fix H-5 (CWE-287): A request where the `viewer_id` in the query
/// does not match the `viewer_id` embedded in the auth token's claims is
/// rejected with `Status::permission_denied()`.
///
/// This tests the identity spoofing prevention: an attacker has a valid token
/// for their own account (`viewer_id = 99002`) but sends a request with
/// `viewer_id = 99001` to access another user's feed. The server validates the
/// token successfully (it's properly signed for 99002), then compares the
/// token's `viewer_id` against `proto_query.viewer_id` and rejects the mismatch.
///
/// Server logic being tested:
/// ```rust,ignore
/// if proto_query.viewer_id == 0 || proto_query.viewer_id != verified_viewer_id as i64 {
///     return Err(Status::permission_denied(
///         "viewer_id does not match authenticated identity",
///     ));
/// }
/// ```
///
/// **Attack vector prevented:** Identity spoofing — an authenticated user
/// setting a different `viewer_id` in the request to access another user's
/// personalized timeline.
#[tokio::test]
async fn test_viewer_id_mismatch_with_token_claims_rejected() {
    setup_test_env();
    let server = HomeMixerServer::new().await;

    // Token is valid for MISMATCHED_VIEWER_ID (99002), but the query
    // contains TEST_VIEWER_ID (99001). The token passes signature verification,
    // but the viewer_id mismatch check catches the spoofing attempt.
    let token_for_other_user = generate_test_auth_token(MISMATCHED_VIEWER_ID as u64);

    let query = make_base_query(TEST_VIEWER_ID); // viewer_id = 99001
    let request = make_request_with_token(query, &token_for_other_user); // token for 99002

    let result = server.get_scored_posts(request).await;

    assert!(
        result.is_err(),
        "Expected PERMISSION_DENIED for viewer_id mismatch, got Ok"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::PermissionDenied,
        "Expected Code::PermissionDenied for viewer_id mismatch, got {:?} with message: {}",
        status.code(),
        status.message()
    );

    assert!(
        status
            .message()
            .contains("viewer_id does not match authenticated identity"),
        "Error message should indicate viewer_id mismatch, got: {}",
        status.message()
    );
}

// ===========================================================================
// Test 7: Auth error messages do not leak internal details
// ===========================================================================

/// Validates Fix H-5 combined with Fix M-1 (CWE-209 / OWASP A09:2025):
/// Authentication error responses do NOT contain internal implementation
/// details such as service names, internal URLs, stack traces, file paths,
/// environment variable names, or cryptographic function names.
///
/// This test sends multiple types of unauthenticated/invalid requests and
/// verifies that every error message is generic and safe for exposure to
/// external callers. The error messages should be limited to:
/// - "Authentication token required"
/// - "Authentication token required: empty token"
/// - "Authentication failed"
/// - "Invalid authentication token format"
/// - "viewer_id does not match authenticated identity"
///
/// **Vulnerability prevented:** CWE-209 — information leakage through verbose
/// error messages that could reveal the internal architecture, technology stack,
/// or credential management approach to an attacker.
#[tokio::test]
async fn test_auth_error_does_not_leak_internal_details() {
    setup_test_env();

    // Wrap the server in Arc to share across multiple verification scenarios
    // without re-constructing (the async pipeline init in new() is expensive).
    // HomeMixerServer derives Clone, and Arc ensures shared ownership semantics
    // consistent with the production gRPC server setup.
    let server = Arc::new(HomeMixerServer::new().await);

    // Scenario A: No auth token at all
    let srv = Arc::clone(&server);
    let query_a = make_base_query(TEST_VIEWER_ID);
    let request_a = make_request_without_token(query_a);
    let result_a = srv.get_scored_posts(request_a).await;
    assert!(result_a.is_err(), "Scenario A should fail (no token)");
    let msg_a = result_a.unwrap_err().message().to_string();
    verify_no_leaked_details(&msg_a, "no-token request");

    // Scenario B: Malformed token (no dots)
    let srv = Arc::clone(&server);
    let query_b = make_base_query(TEST_VIEWER_ID);
    let request_b = make_request_with_token(query_b, "not-a-valid-token");
    let result_b = srv.get_scored_posts(request_b).await;
    assert!(result_b.is_err(), "Scenario B should fail (malformed token)");
    let msg_b = result_b.unwrap_err().message().to_string();
    verify_no_leaked_details(&msg_b, "malformed-token request");

    // Scenario C: Structurally valid token with wrong signature
    let srv = Arc::clone(&server);
    let expiry_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 3600;
    let forged = format!("{}.{}.aaaaaaaaaaaaaaaa", TEST_VIEWER_ID, expiry_secs);
    let query_c = make_base_query(TEST_VIEWER_ID);
    let request_c = make_request_with_token(query_c, &forged);
    let result_c = srv.get_scored_posts(request_c).await;
    assert!(
        result_c.is_err(),
        "Scenario C should fail (wrong signature)"
    );
    let msg_c = result_c.unwrap_err().message().to_string();
    verify_no_leaked_details(&msg_c, "wrong-signature request");

    // Scenario D: Non-ASCII bytes in the token header value
    // tonic::metadata::MetadataValue::from_bytes can produce a binary value,
    // but to_str() on binary metadata returns Err, triggering "Invalid
    // authentication token format". We test with a token containing characters
    // that would fail to_str() expectations. Using a simple ASCII non-printable
    // character isn't possible via from_str, so we test with a token that has
    // non-numeric viewer_id instead.
    let srv = Arc::clone(&server);
    let query_d = make_base_query(TEST_VIEWER_ID);
    let request_d = make_request_with_token(query_d, "abc.def.ghijklmnopqrstuv");
    let result_d = srv.get_scored_posts(request_d).await;
    assert!(
        result_d.is_err(),
        "Scenario D should fail (non-numeric components)"
    );
    let msg_d = result_d.unwrap_err().message().to_string();
    verify_no_leaked_details(&msg_d, "non-numeric-components request");

    // Scenario E: viewer_id mismatch
    let srv = Arc::clone(&server);
    let token_e = generate_test_auth_token(MISMATCHED_VIEWER_ID as u64);
    let query_e = make_base_query(TEST_VIEWER_ID);
    let request_e = make_request_with_token(query_e, &token_e);
    let result_e = srv.get_scored_posts(request_e).await;
    assert!(
        result_e.is_err(),
        "Scenario E should fail (viewer_id mismatch)"
    );
    let msg_e = result_e.unwrap_err().message().to_string();
    verify_no_leaked_details(&msg_e, "viewer_id-mismatch request");
}

/// Asserts that an error message does not contain any of the
/// [`FORBIDDEN_ERROR_SUBSTRINGS`], which would indicate leakage of internal
/// implementation details. Each forbidden substring is checked individually
/// to provide a clear assertion message identifying exactly which leaked
/// detail was found.
fn verify_no_leaked_details(error_message: &str, scenario_label: &str) {
    for &forbidden in FORBIDDEN_ERROR_SUBSTRINGS {
        assert!(
            !error_message.contains(forbidden),
            "Auth error message for {} leaks internal detail '{}'. \
             Full message: '{}'",
            scenario_label,
            forbidden,
            error_message
        );
    }
}
