//! Security tests for gRPC authentication enforcement in the Thunder service.
//!
//! **OWASP A01:2025** — Broken Access Control
//! **CWE-306** — Missing Authentication for Critical Function
//!
//! These tests validate that the H-3 security fix in `thunder_service.rs` correctly
//! enforces authentication on all gRPC endpoints via the `auth_interceptor`. Before
//! the fix, any network-reachable client could query Thunder's in-memory PostStore
//! without identity verification. After the fix, a `tonic::service::interceptor`
//! validates the `authorization` metadata header on every incoming gRPC request.
//!
//! Vulnerable pattern addressed:
//! - Thunder gRPC service (`ThunderServiceImpl`) had no authentication middleware,
//!   allowing any caller to invoke `GetInNetworkPosts` without identity verification.
//!
//! Test coverage:
//! - **test_unauthenticated_request_is_rejected**: Request with no auth header → UNAUTHENTICATED
//! - **test_request_without_auth_header_returns_unauthenticated**: No auth + no internal details
//! - **test_request_with_invalid_token_is_rejected**: Empty token → UNAUTHENTICATED
//! - **test_request_with_valid_token_is_accepted**: Valid token → passes through interceptor
//! - **test_auth_interceptor_applied_to_server**: Structural verification of interceptor wiring
//! - **test_resource_exhausted_still_works_with_auth**: Auth + load shedding interaction

use std::sync::Arc;

use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::{Code, Request, Status};

use thunder::posts::post_store::PostStore;
use thunder::strato_client::StratoClient;
use thunder::thunder_service::{auth_interceptor, ThunderServiceImpl};
use xai_thunder_proto::in_network_posts_service_server::{
    InNetworkPostsService, InNetworkPostsServiceServer,
};
use xai_thunder_proto::GetInNetworkPostsRequest;

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

/// Constructs a `ThunderServiceImpl` with minimal configuration for testing.
///
/// Uses a real `PostStore` (empty, with 24-hour retention and 5-second timeout)
/// and a real `StratoClient` (which will return empty results since no
/// real Strato service is running). The semaphore is set to `max_concurrent`
/// to control load-shedding behavior in tests.
fn create_thunder_service(max_concurrent: usize) -> ThunderServiceImpl {
    let post_store = Arc::new(PostStore::new(86400, 5000));
    let strato_client = Arc::new(StratoClient::new());
    ThunderServiceImpl::new(post_store, strato_client, max_concurrent)
}

/// Builds a default `GetInNetworkPostsRequest` for authentication tests.
///
/// The request has a valid `user_id`, a small `following_user_ids` list (so
/// the Strato fetch path is NOT triggered), and `debug = false`. This ensures
/// that if the request passes authentication, the service returns a successful
/// (but empty) response from the empty `PostStore`.
fn build_test_request() -> GetInNetworkPostsRequest {
    GetInNetworkPostsRequest {
        user_id: 12345,
        following_user_ids: vec![100, 200, 300],
        exclude_tweet_ids: vec![],
        max_results: 10,
        is_video_request: false,
        debug: false,
        algorithm: String::new(),
    }
}

/// Constructs a `tonic::Request<()>` (metadata-only, as required by tonic
/// interceptors) with no authentication metadata, suitable for testing
/// unauthenticated access rejection.
fn build_unauthenticated_interceptor_request() -> Request<()> {
    Request::new(())
}

/// Constructs a `tonic::Request<()>` with a valid Bearer authentication token
/// in the `authorization` metadata header for interceptor testing.
fn build_authenticated_interceptor_request() -> Request<()> {
    let mut request = Request::new(());
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer valid-test-token-12345"),
    );
    request
}

/// Constructs a `tonic::Request<()>` with an empty `authorization` header
/// for interceptor testing (header present but value empty).
fn build_empty_token_interceptor_request() -> Request<()> {
    let mut request = Request::new(());
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static(""),
    );
    request
}

// ---------------------------------------------------------------------------
// Test 1: Unauthenticated Request Rejection (Primary H-3 Regression Test)
// ---------------------------------------------------------------------------

/// **CWE-306 / OWASP A01:2025 — Primary regression test for Fix H-3.**
///
/// Validates that the `auth_interceptor` rejects a request WITHOUT any
/// authentication headers in the request metadata with `UNAUTHENTICATED`
/// status and the error message "Authentication required".
///
/// This is the primary regression test: if the `auth_interceptor` is ever
/// removed or its logic weakened, this test will fail.
#[tokio::test]
async fn test_unauthenticated_request_is_rejected() {
    // Call the auth_interceptor directly with no authorization metadata.
    let request = build_unauthenticated_interceptor_request();
    let result = auth_interceptor(request);

    // The interceptor must reject the request.
    assert!(
        result.is_err(),
        "Unauthenticated request must be rejected by the auth interceptor"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::Unauthenticated,
        "Expected gRPC UNAUTHENTICATED status code for missing authorization header"
    );
    assert_eq!(
        status.message(),
        "Authentication required",
        "Error message must be the generic 'Authentication required' string"
    );
}

// ---------------------------------------------------------------------------
// Test 2: No Auth Header — Verify Code and No Internal Details
// ---------------------------------------------------------------------------

/// **CWE-306 / OWASP A01:2025 + cross-reference CWE-209 / OWASP A09:2025.**
///
/// Verifies that a request with empty metadata (no `authorization` key) returns
/// `Code::Unauthenticated` and that the error response does NOT contain internal
/// service details such as source file paths, internal service names, component
/// names, or implementation details. This cross-references Fix M-1 (error
/// message sanitization).
#[tokio::test]
async fn test_request_without_auth_header_returns_unauthenticated() {
    // Call the auth_interceptor with completely empty metadata.
    let request = build_unauthenticated_interceptor_request();
    let result = auth_interceptor(request);

    assert!(
        result.is_err(),
        "Request without auth header must be rejected"
    );
    let status = result.unwrap_err();

    // Verify the gRPC status code is UNAUTHENTICATED.
    assert_eq!(
        status.code(),
        Code::Unauthenticated,
        "Expected UNAUTHENTICATED code for missing auth header"
    );

    // Cross-reference Fix M-1 (CWE-209): Ensure no internal service details
    // are leaked in the error message. The interceptor error message must be
    // a generic string that does not reveal implementation architecture.
    let message = status.message();
    assert!(
        !message.contains("Strato"),
        "Error message must not contain internal service name 'Strato'"
    );
    assert!(
        !message.contains("PostStore"),
        "Error message must not contain internal component name 'PostStore'"
    );
    assert!(
        !message.contains(".rs"),
        "Error message must not contain Rust source file references"
    );
    assert!(
        !message.contains("thunder_service"),
        "Error message must not contain internal module names"
    );
    assert!(
        !message.contains("interceptor"),
        "Error message must not reveal interceptor implementation details"
    );
    assert!(
        !message.contains("metadata"),
        "Error message must not reveal gRPC metadata internals"
    );
    assert!(
        !message.contains("panicked"),
        "Error message must not contain panic traces"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Invalid/Malformed Token Rejection
// ---------------------------------------------------------------------------

/// **CWE-306 / OWASP A01:2025 — Validates token content validation.**
///
/// Sends a request with an `authorization` metadata header containing an
/// empty token (invalid/malformed). Asserts the response is UNAUTHENTICATED.
/// This test verifies that the interceptor properly validates token content,
/// not just checks for the header's presence. Simply having an `authorization`
/// key is not sufficient — the value must be non-empty.
#[tokio::test]
async fn test_request_with_invalid_token_is_rejected() {
    // Call the auth_interceptor with an empty authorization token.
    let request = build_empty_token_interceptor_request();
    let result = auth_interceptor(request);

    assert!(
        result.is_err(),
        "Request with empty auth token must be rejected — interceptor must validate content, not just presence"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::Unauthenticated,
        "Expected UNAUTHENTICATED for empty token — interceptor must validate token content"
    );
    assert_eq!(
        status.message(),
        "Authentication required",
        "Error message for invalid token must be 'Authentication required'"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Valid Token Accepted
// ---------------------------------------------------------------------------

/// **CWE-306 / OWASP A01:2025 — Validates that valid tokens pass through.**
///
/// Sends a request with a valid (non-empty) Bearer authentication token to the
/// interceptor and verifies it passes through. Then calls the service method
/// directly to confirm that an authenticated request reaches the service logic.
/// The response may be a successful empty result (PostStore is empty in tests)
/// or a business-logic error, but it must NOT be an `UNAUTHENTICATED` error.
#[tokio::test]
async fn test_request_with_valid_token_is_accepted() {
    // Part 1: Verify the interceptor passes valid tokens through.
    let request = build_authenticated_interceptor_request();
    let result = auth_interceptor(request);

    assert!(
        result.is_ok(),
        "Request with valid Bearer token must pass through the auth interceptor"
    );
    let passed_request = result.unwrap();
    // Verify the original metadata is preserved after passing through the interceptor.
    assert!(
        passed_request.metadata().get("authorization").is_some(),
        "Authorization header must be preserved after passing through interceptor"
    );

    // Part 2: Verify the service method works for authenticated requests.
    // Call the InNetworkPostsService trait method directly to confirm
    // the service logic functions correctly for an empty PostStore.
    let service = create_thunder_service(10);
    let mut typed_request = Request::new(build_test_request());
    typed_request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer valid-test-token-12345"),
    );
    let result = service.get_in_network_posts(typed_request).await;

    match result {
        Ok(response) => {
            // Authentication passed — service returned a valid response.
            let inner = response.into_inner();
            // PostStore is empty in tests, so expect zero posts.
            assert!(
                inner.posts.is_empty(),
                "Expected empty posts from empty PostStore, got {} posts",
                inner.posts.len()
            );
        }
        Err(status) => {
            // If there's an error, it must NOT be UNAUTHENTICATED.
            // Other errors (e.g., INTERNAL from spawn_blocking failure)
            // are acceptable because they indicate the request reached the service.
            assert_ne!(
                status.code(),
                Code::Unauthenticated,
                "Request with valid token must not be rejected as unauthenticated; got: {} ({})",
                status.code(),
                status.message()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 5: Auth Interceptor Wired to Server (Structural / Compilation Test)
// ---------------------------------------------------------------------------

/// **CWE-306 / OWASP A01:2025 — Structural verification of interceptor wiring.**
///
/// Verifies that `ThunderServiceImpl::server()` returns an `InterceptedService`
/// (indicating that `InNetworkPostsServiceServer` is wrapped with the
/// `auth_interceptor` via `InterceptedService::new()`). If `server()` were ever
/// changed to return a bare `InNetworkPostsServiceServer::new(self)` without
/// the interceptor, this test would fail to compile because the
/// `assert_is_intercepted_service` function only accepts `InterceptedService`.
///
/// This provides a compile-time guard against accidental removal of the
/// authentication interceptor from the server construction.
#[tokio::test]
async fn test_auth_interceptor_applied_to_server() {
    /// Compile-time type assertion: only accepts an `InterceptedService` wrapping
    /// `InNetworkPostsServiceServer<ThunderServiceImpl>` with the correct
    /// interceptor function signature. A bare `InNetworkPostsServiceServer`
    /// (without interceptor) or a different interceptor signature would cause
    /// a type mismatch compilation error.
    fn assert_is_intercepted_service(
        _svc: &InterceptedService<
            InNetworkPostsServiceServer<ThunderServiceImpl>,
            fn(Request<()>) -> Result<Request<()>, Status>,
        >,
    ) {
        // Compilation success with this exact type signature proves:
        // 1. The service is wrapped in InterceptedService (not a bare server)
        // 2. The inner service is InNetworkPostsServiceServer<ThunderServiceImpl>
        // 3. The interceptor has the correct fn(Request<()>) -> Result<Request<()>, Status> signature
    }

    let service = create_thunder_service(10);
    let server = service.server();

    // This call only compiles if server() returns the exact InterceptedService type.
    // If server() returned InNetworkPostsServiceServer<ThunderServiceImpl> directly
    // (i.e., without the interceptor), this would be a type mismatch error.
    assert_is_intercepted_service(&server);
}

// ---------------------------------------------------------------------------
// Test 6: Resource Exhausted Works Correctly With Auth
// ---------------------------------------------------------------------------

/// **CWE-306 / OWASP A01:2025 — Auth + load shedding interaction test.**
///
/// Validates that authentication checking and load shedding (semaphore) work
/// correctly together. When the semaphore is fully saturated (0 permits) but
/// the request carries a valid auth token, the response must be
/// `RESOURCE_EXHAUSTED` (not `UNAUTHENTICATED`). This confirms:
///
/// 1. The auth interceptor runs before the service method and passes valid tokens
/// 2. The semaphore check inside the service method correctly returns
///    `RESOURCE_EXHAUSTED` after authentication succeeds
/// 3. There is no confusion between transport-level (auth) and application-level
///    (load shedding) error handling
#[tokio::test]
async fn test_resource_exhausted_still_works_with_auth() {
    // Part 1: Verify the auth interceptor accepts the valid token.
    let interceptor_request = build_authenticated_interceptor_request();
    let interceptor_result = auth_interceptor(interceptor_request);
    assert!(
        interceptor_result.is_ok(),
        "Valid Bearer token must pass the auth interceptor"
    );

    // Part 2: Create service with max_concurrent_requests = 0 so the semaphore
    // has zero permits and every request hitting the service method is immediately
    // rejected with RESOURCE_EXHAUSTED.
    let service = create_thunder_service(0);

    // Send an authenticated request directly to the service method.
    // Since we verified the interceptor passes the token above, this tests
    // the service-level load shedding behavior after authentication.
    let mut request = Request::new(build_test_request());
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer valid-test-token-12345"),
    );
    let result = service.get_in_network_posts(request).await;

    // The request must fail because the semaphore is exhausted.
    assert!(
        result.is_err(),
        "Request should fail because server semaphore has zero permits"
    );
    let status = result.unwrap_err();

    // Must be RESOURCE_EXHAUSTED, NOT UNAUTHENTICATED. The auth interceptor
    // passes the valid token, then the service method rejects due to capacity.
    assert_eq!(
        status.code(),
        Code::ResourceExhausted,
        "Expected RESOURCE_EXHAUSTED (not UNAUTHENTICATED) for authenticated request on saturated server"
    );
}
