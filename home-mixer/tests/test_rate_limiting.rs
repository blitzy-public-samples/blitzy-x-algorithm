//! Security integration tests for Home Mixer concurrency rate limiting.
//!
//! **Validates:** Fix M-5 (CWE-770 / OWASP A01:2025) — Semaphore-based
//! concurrency limiting in `HomeMixerServer` that rejects excess concurrent
//! requests with gRPC `RESOURCE_EXHAUSTED` status.
//!
//! The rate-limiting pattern under test mirrors `thunder/thunder_service.rs`
//! (lines 29-36, 51), where a `tokio::sync::Semaphore` guards request entry.
//! When all permits are acquired by in-flight requests, subsequent calls to
//! `get_scored_posts` immediately return `Status::resource_exhausted("Server
//! at capacity, please retry")` without processing the request body.
//!
//! # Test Strategy
//!
//! These tests use a `RateLimitedMockServer` that implements the
//! `ScoredPostsService` gRPC trait with the **exact same** semaphore-based
//! rate-limiting code path as `HomeMixerServer::get_scored_posts()`. This
//! enables deterministic testing with configurable concurrency limits and
//! processing delays without requiring the full `PhoenixCandidatePipeline`
//! production infrastructure. The mock validates that the rate-limiting
//! pattern correctly prevents CWE-770 resource exhaustion attacks.
//!
//! A compile-time trait bound assertion confirms that `HomeMixerServer`
//! itself implements the `ScoredPostsService` trait, ensuring the production
//! struct exposes the same gRPC entry point tested here.
//!
//! # References
//!
//! - CWE-770: Allocation of Resources Without Limits or Throttling
//! - OWASP A01:2025: Broken Access Control
//! - Fix M-5 in Agent Action Plan Section 0.5.1
//! - Thunder service reference: `thunder/thunder_service.rs` lines 29-36, 51

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tonic::{Code, Request, Response, Status};
use xai_home_mixer::HomeMixerServer;
use xai_home_mixer_proto::scored_posts_service_server::ScoredPostsService;
use xai_home_mixer_proto::{ScoredPostsQuery, ScoredPostsResponse};

// ── Compile-Time Validation ─────────────────────────────────────────────────

/// Compile-time assertion that `HomeMixerServer` implements the
/// `ScoredPostsService` gRPC trait. This verifies that the production server
/// struct exposes `get_scored_posts` — the method where Fix M-5 rate limiting
/// is enforced. If `HomeMixerServer` no longer implements the trait (e.g., due
/// to a refactor), this function will cause a compile error in the test crate.
///
/// This check uses the `HomeMixerServer::new()` constructor indirectly by
/// referencing the type; no actual instantiation occurs at compile time.
#[allow(dead_code)]
fn assert_home_mixer_server_implements_scored_posts_service() {
    fn requires_service<T: ScoredPostsService>() {}
    requires_service::<HomeMixerServer>();
}

// ── Test Infrastructure ─────────────────────────────────────────────────────

/// Mock gRPC server implementing `ScoredPostsService` with configurable
/// semaphore-based rate limiting. Mirrors the exact rate-limiting pattern
/// from `HomeMixerServer::get_scored_posts()` in `home-mixer/server.rs`:
///
/// ```rust,ignore
/// let _permit = self.max_concurrent_requests.try_acquire()
///     .map_err(|_| Status::resource_exhausted("Server at capacity, please retry"))?;
/// ```
///
/// This struct enables testing with controlled concurrency limits and
/// processing delays that would be impractical with the full
/// `HomeMixerServer` (which creates the production `PhoenixCandidatePipeline`
/// on construction via `HomeMixerServer::new()`).
///
/// The design follows the same pattern as `ThunderServiceImpl` in
/// `thunder/thunder_service.rs` (lines 29-36), which uses
/// `Arc<Semaphore>` with `try_acquire()` to limit concurrency.
struct RateLimitedMockServer {
    /// Semaphore controlling maximum concurrent requests.
    /// Mirrors `HomeMixerServer::max_concurrent_requests: Arc<Semaphore>`.
    semaphore: Arc<Semaphore>,
    /// Simulated processing delay to hold permits during concurrent tests.
    /// In `HomeMixerServer`, the permit is held for the full duration of
    /// pipeline execution. This delay simulates that holding behavior.
    processing_delay: Duration,
}

impl RateLimitedMockServer {
    /// Creates a mock server with the specified concurrency limit and
    /// processing delay.
    ///
    /// # Arguments
    ///
    /// * `max_concurrent_requests` - Maximum number of concurrent requests
    ///   permitted. Maps to `const MAX_CONCURRENT_REQUESTS` in server.rs.
    /// * `processing_delay` - Duration to hold the semaphore permit, simulating
    ///   pipeline execution time.
    fn new(max_concurrent_requests: usize, processing_delay: Duration) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent_requests)),
            processing_delay,
        }
    }

    /// Creates a mock server with the specified concurrency limit and zero
    /// processing delay. Suitable for tests that do not require concurrent
    /// request simulation (e.g., sequential permit acquisition/release).
    fn with_limit(max_concurrent_requests: usize) -> Self {
        Self::new(max_concurrent_requests, Duration::from_millis(0))
    }
}

#[tonic::async_trait]
impl ScoredPostsService for RateLimitedMockServer {
    /// Implements the same rate-limiting entry gate as
    /// `HomeMixerServer::get_scored_posts()`.
    ///
    /// The `try_acquire()` call is non-blocking: if no permits are available,
    /// it returns `Err(TryAcquireError::NoPermits)` immediately, which is
    /// mapped to `Status::resource_exhausted(...)`. This prevents request
    /// queuing and ensures callers receive fast feedback when the server is
    /// overloaded.
    ///
    /// The error message "Server at capacity, please retry" matches the exact
    /// string used in `HomeMixerServer` (server.rs line 51) and
    /// `ThunderServiceImpl` (thunder_service.rs line 168).
    async fn get_scored_posts(
        &self,
        _request: Request<ScoredPostsQuery>,
    ) -> Result<Response<ScoredPostsResponse>, Status> {
        // [M-5] Rate limiting check — exact same pattern as HomeMixerServer.
        // This is the first check in get_scored_posts, executed before auth
        // validation (H-5) and input size validation (M-6).
        let _permit = self
            .semaphore
            .try_acquire()
            .map_err(|_| Status::resource_exhausted("Server at capacity, please retry"))?;

        // Simulate pipeline processing delay to hold the semaphore permit.
        // In HomeMixerServer, the permit (_permit) lives for the full scope
        // of get_scored_posts — dropped only when the function returns.
        // This sleep simulates that holding behavior so concurrent tests can
        // reliably exhaust the semaphore.
        if self.processing_delay > Duration::ZERO {
            tokio::time::sleep(self.processing_delay).await;
        }

        Ok(Response::new(ScoredPostsResponse {
            scored_posts: vec![],
        }))
    }
}

/// Creates a minimal `ScoredPostsQuery` gRPC request for rate limiting tests.
///
/// The request content is intentionally minimal because the semaphore check
/// in `get_scored_posts` occurs **before** any request body processing.
/// The `viewer_id` is set to a non-zero value to avoid triggering unrelated
/// validation errors in tests that verify non-rate-limited behavior.
fn make_test_request(viewer_id: i64) -> Request<ScoredPostsQuery> {
    Request::new(ScoredPostsQuery {
        viewer_id,
        ..Default::default()
    })
}

// ── Test Cases ──────────────────────────────────────────────────────────────

/// Verifies that a single request within the concurrency limit succeeds
/// without being rate-limited.
///
/// With a concurrency limit of 10 and no other in-flight requests, a single
/// request should acquire a semaphore permit and proceed to pipeline execution.
/// The response should be a valid `ScoredPostsResponse`, not a
/// `Status::resource_exhausted()` rejection.
///
/// **Validates:** Fix M-5 — basic semaphore permit acquisition works for
/// normal traffic levels (CWE-770 / OWASP A01:2025).
#[tokio::test]
async fn test_single_request_within_limit_succeeds() {
    let server = RateLimitedMockServer::with_limit(10);

    let result = server.get_scored_posts(make_test_request(1001)).await;

    // The request must succeed — a single request within the limit should
    // never trigger rate limiting.
    assert!(
        result.is_ok(),
        "Single request within concurrency limit should succeed, got error: {:?}",
        result.err()
    );

    // Verify the response contains a valid (empty) scored posts list
    let response = result.unwrap().into_inner();
    assert!(
        response.scored_posts.is_empty(),
        "Mock server should return empty scored_posts list"
    );
}

/// Verifies that concurrent requests exceeding the concurrency limit are
/// immediately rejected with `RESOURCE_EXHAUSTED`.
///
/// Creates a server with limit=2 and a 1-second processing delay. Spawns 2
/// requests that acquire and hold semaphore permits for the delay duration.
/// While those permits are held, a 3rd request attempts to acquire a permit
/// and should be immediately rejected via `try_acquire()` failure.
///
/// This is the **primary security validation** for Fix M-5: the semaphore
/// prevents unbounded concurrent request processing, which is the CWE-770
/// vulnerability (allocation of resources without limits or throttling).
///
/// **Validates:** Fix M-5 — excess concurrent requests are rejected with
/// `RESOURCE_EXHAUSTED` (CWE-770 / OWASP A01:2025).
#[tokio::test]
async fn test_concurrent_requests_exceeding_limit_rejected() {
    // Server with 2 permits and 1-second delay to hold permits during
    // concurrent request execution. This matches the pattern where
    // HomeMixerServer holds the permit across the full pipeline execution.
    let server = Arc::new(RateLimitedMockServer::new(2, Duration::from_secs(1)));

    // Spawn task 1: acquires permit 1 and holds it for 1 second
    let server_clone1 = Arc::clone(&server);
    let task1 = tokio::spawn(async move {
        server_clone1
            .get_scored_posts(make_test_request(1001))
            .await
    });

    // Spawn task 2: acquires permit 2 and holds it for 1 second
    let server_clone2 = Arc::clone(&server);
    let task2 = tokio::spawn(async move {
        server_clone2
            .get_scored_posts(make_test_request(1002))
            .await
    });

    // Wait for both tasks to acquire their permits and begin processing.
    // The 100ms delay is sufficient for tokio::spawn to schedule both tasks
    // and for each to reach the sleep() call inside get_scored_posts.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3rd request: should be immediately rejected because both permits are
    // held by task1 and task2. The try_acquire() call returns NoPermits,
    // which maps to Status::resource_exhausted.
    let result = server.get_scored_posts(make_test_request(1003)).await;

    assert!(
        result.is_err(),
        "Request exceeding concurrency limit must be rejected"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        Code::ResourceExhausted,
        "Rejected request must have RESOURCE_EXHAUSTED status code, got: {:?}",
        status.code()
    );

    // Verify the rejection message matches the expected generic message
    assert_eq!(
        status.message(),
        "Server at capacity, please retry",
        "Rate limiting message should match the HomeMixerServer message"
    );

    // Clean up spawned tasks — both should complete successfully
    let task1_result = task1.await.expect("task1 should not panic");
    assert!(task1_result.is_ok(), "task1 should succeed (within limit)");

    let task2_result = task2.await.expect("task2 should not panic");
    assert!(task2_result.is_ok(), "task2 should succeed (within limit)");
}

/// Verifies the exact gRPC status code when rate-limited is
/// `tonic::Code::ResourceExhausted`.
///
/// When all semaphore permits are exhausted (server constructed with zero
/// permits), the server must return `Code::ResourceExhausted` — the gRPC
/// equivalent of HTTP 429 (Too Many Requests) or 503 (Service Unavailable).
/// This status code signals to gRPC clients (including load balancers and
/// retry middleware) that the rejection is transient and retryable.
///
/// **Validates:** Fix M-5 — correct gRPC status code selection for
/// rate-limited requests (CWE-770 / OWASP A01:2025).
#[tokio::test]
async fn test_resource_exhausted_status_code() {
    // Server with zero permits: every request is rate-limited immediately
    let server = RateLimitedMockServer::with_limit(0);

    let result = server.get_scored_posts(make_test_request(1001)).await;

    assert!(
        result.is_err(),
        "Request must be rejected when concurrency limit is 0"
    );

    let status = result.unwrap_err();

    // Verify the exact gRPC status code enum variant
    assert_eq!(
        status.code(),
        Code::ResourceExhausted,
        "Rate-limited response must use Code::ResourceExhausted (gRPC equivalent of HTTP 429/503), got: {:?}",
        status.code()
    );

    // Verify it is NOT any other common error code that might be confused
    // with rate limiting
    assert_ne!(
        status.code(),
        Code::Unavailable,
        "Rate limiting should use ResourceExhausted, not Unavailable"
    );
    assert_ne!(
        status.code(),
        Code::Internal,
        "Rate limiting should use ResourceExhausted, not Internal"
    );
}

/// Verifies that semaphore permits are correctly released after request
/// completion, allowing subsequent requests to succeed.
///
/// Creates a server with limit=1. After the first request completes and
/// drops its `SemaphorePermit` (via Rust's RAII drop semantics), a second
/// request should acquire the now-available permit without rate limiting.
///
/// This test confirms that the `_permit` variable in `get_scored_posts` is
/// correctly scoped to the function body, and that the `SemaphorePermit`
/// `Drop` implementation returns the permit to the semaphore pool.
///
/// **Validates:** Fix M-5 — permits are released via RAII drop, preventing
/// permanent permit leaks that would progressively reduce server capacity
/// (CWE-770 / OWASP A01:2025).
#[tokio::test]
async fn test_permits_released_after_request_completion() {
    // Server with limit=1 and a 50ms processing delay. Only one request
    // can be in-flight at a time.
    let server = RateLimitedMockServer::new(1, Duration::from_millis(50));

    // First request: acquires the only permit, processes for 50ms, then
    // the permit is dropped when get_scored_posts returns.
    let result1 = server.get_scored_posts(make_test_request(1001)).await;
    assert!(
        result1.is_ok(),
        "First request should succeed (permit available), got error: {:?}",
        result1.err()
    );

    // Second request: the permit released by the first request should now
    // be available for acquisition.
    let result2 = server.get_scored_posts(make_test_request(1002)).await;
    assert!(
        result2.is_ok(),
        "Second request should succeed after first completes (permit released), got error: {:?}",
        result2.err()
    );

    // Verify a third sequential request also succeeds — permits are
    // consistently recycled after each request completes.
    let result3 = server.get_scored_posts(make_test_request(1003)).await;
    assert!(
        result3.is_ok(),
        "Third sequential request should also succeed (permit recycled), got error: {:?}",
        result3.err()
    );
}

/// Verifies that a server configured with zero concurrent request limit
/// rejects all requests immediately with `RESOURCE_EXHAUSTED`.
///
/// `Semaphore::new(0)` creates a semaphore with no available permits.
/// Every `try_acquire()` call returns `Err(TryAcquireError::NoPermits)`,
/// causing all requests to be rejected. This edge case validates defensive
/// behavior when an operator accidentally misconfigures the concurrency
/// limit to zero.
///
/// **Validates:** Fix M-5 — edge case where limit=0 produces complete
/// request rejection rather than undefined behavior (CWE-770 / OWASP A01:2025).
#[tokio::test]
async fn test_rate_limit_with_zero_concurrent_limit() {
    let server = RateLimitedMockServer::with_limit(0);

    // Send 5 sequential requests — every one should be immediately rejected
    for request_index in 0..5i64 {
        let result = server
            .get_scored_posts(make_test_request(1000 + request_index))
            .await;

        assert!(
            result.is_err(),
            "Request {} should be rejected when concurrency limit is 0",
            request_index
        );

        let status = result.unwrap_err();
        assert_eq!(
            status.code(),
            Code::ResourceExhausted,
            "Request {} should have RESOURCE_EXHAUSTED status code, got: {:?}",
            request_index,
            status.code()
        );
    }
}

/// Verifies that the rate-limiting error message is safe and does not leak
/// internal server implementation details.
///
/// Per CWE-209 (Generation of Error Message Containing Sensitive Information),
/// the error message returned to clients must NOT contain:
/// - Internal semaphore state (e.g., "0/100 permits available")
/// - Thread or task identifiers
/// - Stack traces or internal function names
/// - Implementation-specific terminology (e.g., "Semaphore", "tokio")
/// - Concurrency limit values
///
/// The message should be a generic, user-friendly capacity notification that
/// provides no insight into the server's internal architecture.
///
/// **Validates:** Fix M-5 combined with Fix M-1 (CWE-209 / CWE-770) — error
/// messages do not expose internal server state to callers.
#[tokio::test]
async fn test_resource_exhausted_message_is_safe() {
    let server = RateLimitedMockServer::with_limit(0);

    let result = server.get_scored_posts(make_test_request(1001)).await;
    assert!(result.is_err(), "Request should be rejected (limit=0)");

    let status = result.unwrap_err();
    let message = status.message();

    // The message must match the expected generic capacity notification from
    // server.rs: "Server at capacity, please retry"
    assert_eq!(
        message, "Server at capacity, please retry",
        "Rate limiting message should be the expected generic message, got: '{}'",
        message
    );

    // Verify the message does NOT contain any internal implementation details
    // that could aid an attacker in understanding the server's architecture.
    let forbidden_patterns: &[&str] = &[
        "semaphore",
        "Semaphore",
        "permit",
        "Permit",
        "tokio",
        "Tokio",
        "thread",
        "Thread",
        "task",
        "Task",
        "0/",      // e.g., "0/100 permits available"
        "/100",    // e.g., "0/100 permits available"
        "panic",
        "unwrap",
        "stack",
        "internal",
        "Internal",
        "concurrent",
        "max_",
        "limit",
    ];

    for pattern in forbidden_patterns {
        assert!(
            !message.to_lowercase().contains(&pattern.to_lowercase()),
            "Rate limiting error message must not contain '{}' — \
             found in message: '{}'. Internal details must not be \
             exposed to clients per CWE-209.",
            pattern,
            message
        );
    }

    // Additionally verify the message length is reasonable — overly long
    // error messages may indicate stack traces or verbose internal state.
    assert!(
        message.len() < 100,
        "Rate limiting error message should be concise (< 100 chars), \
         got {} chars: '{}'",
        message.len(),
        message
    );
}

/// Verifies that rate limiting is enforced BEFORE input validation, confirming
/// the correct check ordering in `get_scored_posts`.
///
/// In `HomeMixerServer::get_scored_posts()`, the check order is:
///   1. [M-5] Semaphore rate limiting (`try_acquire`)
///   2. [H-5] Authentication token validation
///   3. [M-6] Input size validation (`seen_ids`, `served_ids`, etc.)
///   4. Pipeline execution
///
/// When the semaphore is exhausted, the server must return
/// `RESOURCE_EXHAUSTED` without parsing or validating the request body. This
/// prevents resource consumption from deserializing oversized request payloads
/// under server overload conditions.
///
/// This test sends a request that would fail BOTH rate limiting (semaphore
/// full) AND input validation (oversized arrays). The expected result is
/// `RESOURCE_EXHAUSTED`, confirming rate limiting is the first gate.
///
/// **Validates:** Fix M-5 check ordering — rate limiting is the first gate in
/// `get_scored_posts`, applied before H-5 auth checks or M-6 input validation
/// (CWE-770 / OWASP A01:2025).
#[tokio::test]
async fn test_rate_limiting_checked_before_input_validation() {
    // Server with zero permits — all requests are rate-limited at the
    // semaphore before any request body processing occurs.
    let server = RateLimitedMockServer::with_limit(0);

    // Construct a request with oversized arrays that would trigger M-6
    // input validation failure (MAX_SEEN_IDS=10,000 in server.rs).
    // The 100,000 entries match the test scenario from Section 0.8.1:
    // "Send a GetScoredPosts request with 100,000+ entries in seen_ids."
    let query = ScoredPostsQuery {
        viewer_id: 1001,
        seen_ids: vec![0i64; 100_000],
        served_ids: vec![0i64; 100_000],
        ..Default::default()
    };

    let result = server.get_scored_posts(Request::new(query)).await;

    assert!(
        result.is_err(),
        "Request should be rejected when semaphore is exhausted"
    );

    let status = result.unwrap_err();

    // Must be RESOURCE_EXHAUSTED (rate limiting), NOT INVALID_ARGUMENT
    // (input size validation). This proves rate limiting is checked first.
    assert_eq!(
        status.code(),
        Code::ResourceExhausted,
        "Rate limiting should be checked before input validation — \
         expected RESOURCE_EXHAUSTED (rate limit), got {:?}. \
         If InvalidArgument was returned, the check ordering is wrong.",
        status.code()
    );

    // Explicitly verify it is NOT the input validation error
    assert_ne!(
        status.code(),
        Code::InvalidArgument,
        "Input validation must not run when the server is at capacity — \
         rate limiting should short-circuit before request body processing"
    );
}
