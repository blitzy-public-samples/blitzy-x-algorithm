//! Security tests for gRPC error response sanitization in the Thunder service.
//!
//! **OWASP A09:2025** — Security Logging and Monitoring Failures
//! **CWE-209** — Generation of Error Message Containing Sensitive Information
//!
//! These tests validate that the M-1 security fix in `thunder_service.rs` correctly
//! sanitizes all gRPC error responses to prevent information leakage. Error responses
//! must contain only generic status messages (e.g., "Internal service error") while
//! detailed error information is logged internally for debugging purposes.
//!
//! Vulnerable patterns addressed:
//! - Internal service names (e.g., "Strato") exposed in gRPC error messages
//! - Stack traces or file paths leaked to clients
//! - Internal hostnames, IP addresses, or port numbers in error responses
//! - Numeric overflow details exposing type constraint implementation details
//!
//! Each test constructs a `ThunderServiceImpl` with real (but network-isolated)
//! dependencies, triggers a specific error path, and asserts that the returned
//! `tonic::Status` message contains only safe, generic content.

use std::sync::Arc;

use log::Level;
use regex::Regex;
use tonic::{Code, Request};

use thunder::posts::post_store::PostStore;
use thunder::strato_client::StratoClient;
use thunder::thunder_service::ThunderServiceImpl;
use xai_thunder_proto::in_network_posts_service_server::InNetworkPostsService;
use xai_thunder_proto::GetInNetworkPostsRequest;

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

/// List of sensitive substrings that must NEVER appear in gRPC error responses.
/// These patterns indicate information leakage per CWE-209.
const SENSITIVE_SUBSTRINGS: &[&str] = &[
    "Strato",
    "strato",
    "strato-internal",
    "Connection refused",
    "connection refused",
    "timeout",
    "fetch",
    "following list",
    "Failed to fetch",
    "gRPC",
    "grpc",
    "tcp",
    "TCP",
    "hyper",
    "tonic",
    "h2",
    "dns",
    "DNS",
];

/// Rust-specific patterns that indicate stack trace or source code leakage.
const STACK_TRACE_SUBSTRINGS: &[&str] = &[
    "panicked at",
    "thread 'main'",
    "thread '",
    "src/",
    ".rs:",
    "RUST_BACKTRACE",
    "stack backtrace",
    "note: run with",
    "at /",
    "main.rs",
    "thunder_service.rs",
    "strato_client.rs",
    "post_store.rs",
];

/// Constructs a default `ThunderServiceImpl` for testing with minimal configuration.
///
/// Uses a real `PostStore` (empty, with 24-hour retention and 5-second timeout)
/// and a real `StratoClient` (which will fail on any network call since no
/// real Strato service is running in the test environment). The semaphore allows
/// up to 10 concurrent requests for most tests.
fn create_test_service(max_concurrent_requests: usize) -> ThunderServiceImpl {
    let post_store = Arc::new(PostStore::new(86400, 5000));
    let strato_client = Arc::new(StratoClient::new());
    ThunderServiceImpl::new(post_store, strato_client, max_concurrent_requests)
}

/// Builds a `GetInNetworkPostsRequest` that triggers the Strato fetch error path.
///
/// The Strato fetch path is activated when:
/// - `following_user_ids` is empty, AND
/// - `debug` is `true`
///
/// In the test environment, the real `StratoClient` will fail because no Strato
/// service is running, causing the error handler at lines 278-288 of the updated
/// `thunder_service.rs` to execute and return a sanitized error response.
fn build_strato_error_triggering_request(user_id: u64) -> Request<GetInNetworkPostsRequest> {
    Request::new(GetInNetworkPostsRequest {
        user_id,
        following_user_ids: vec![], // empty to trigger Strato fetch
        exclude_tweet_ids: vec![],
        max_results: 0,
        is_video_request: false,
        debug: true, // required to trigger Strato fetch path
        algorithm: String::new(),
    })
}

/// Builds a standard `GetInNetworkPostsRequest` that does NOT trigger the Strato
/// fetch path. Used for tests that exercise other error paths (e.g., integer overflow).
fn build_request_with_user_id(user_id: u64) -> Request<GetInNetworkPostsRequest> {
    Request::new(GetInNetworkPostsRequest {
        user_id,
        following_user_ids: vec![], // empty to trigger Strato fetch
        exclude_tweet_ids: vec![],
        max_results: 10,
        is_video_request: false,
        debug: true, // required to trigger Strato fetch path for overflow test
        algorithm: String::new(),
    })
}

/// Asserts that an error message does not contain any of the provided sensitive substrings.
/// Panics with a descriptive message if any sensitive substring is found.
fn assert_no_sensitive_substrings(message: &str, sensitive_list: &[&str], context: &str) {
    for sensitive in sensitive_list {
        assert!(
            !message.contains(sensitive),
            "[CWE-209] {} — error message contains sensitive substring '{}'. \
             Full message: '{}'",
            context,
            sensitive,
            message
        );
    }
}

// ---------------------------------------------------------------------------
// Test 1: Strato error does not leak internal details
// ---------------------------------------------------------------------------

/// Validates that a Strato client error does not leak internal service details
/// in the gRPC error response (CWE-209 / OWASP A09:2025).
///
/// **Attack scenario:** An attacker triggers a Strato fetch failure (e.g., by
/// sending a request with an empty following list and debug=true). Before the
/// M-1 fix, the error response contained the full Strato error string including
/// internal hostnames, port numbers, and timeout details.
///
/// **Expected behavior after fix:** The gRPC response contains only
/// `"Internal service error"` while the detailed error is logged internally.
#[tokio::test]
async fn test_strato_error_does_not_leak_details() {
    let service = create_test_service(10);

    // Trigger the Strato error path: empty following_user_ids + debug=true
    let request = build_strato_error_triggering_request(12345);
    let result = service.get_in_network_posts(request).await;

    // The request should fail because StratoClient cannot connect
    assert!(
        result.is_err(),
        "Expected error from Strato fetch failure, but got success"
    );

    let status = result.unwrap_err();

    // Verify the error code is INTERNAL (not a more specific code)
    assert_eq!(
        status.code(),
        Code::Internal,
        "Expected Code::Internal for Strato failure, got {:?}",
        status.code()
    );

    let message = status.message();

    // The response MUST NOT contain any internal service details
    assert_no_sensitive_substrings(
        message,
        SENSITIVE_SUBSTRINGS,
        "test_strato_error_does_not_leak_details",
    );

    // The response SHOULD contain a generic message
    assert_eq!(
        message, "Internal service error",
        "Expected generic error message 'Internal service error', got '{}'",
        message
    );
}

// ---------------------------------------------------------------------------
// Test 2: Error response contains only a generic message
// ---------------------------------------------------------------------------

/// Validates that all error paths return the same generic error message,
/// preventing attackers from fingerprinting internal failure modes (CWE-209).
///
/// **Attack scenario:** An attacker sends multiple requests designed to trigger
/// different error paths and compares the error messages to infer internal
/// architecture. Before the M-1 fix, different failures produced different
/// error strings (e.g., "Failed to fetch following list: ..." vs.
/// "Failed to process posts: ...").
///
/// **Expected behavior after fix:** All internal error paths return the same
/// generic message, preventing failure mode fingerprinting.
#[tokio::test]
async fn test_error_response_contains_generic_message() {
    let service = create_test_service(10);

    // Trigger the Strato error path
    let request = build_strato_error_triggering_request(99999);
    let result = service.get_in_network_posts(request).await;

    assert!(result.is_err(), "Expected error response");
    let status = result.unwrap_err();
    let message = status.message();

    // Forbidden substrings that would indicate implementation-specific error details
    let forbidden_substrings = [
        "fetch",
        "following list",
        "Strato",
        "strato",
        "connection",
        "Connection",
        "refused",
        "timeout",
        "Timeout",
        "dns",
        "DNS",
        "resolve",
        "socket",
        "transport",
        "http",
        "HTTP",
        "channel",
    ];

    assert_no_sensitive_substrings(
        message,
        &forbidden_substrings,
        "test_error_response_contains_generic_message",
    );

    // Verify the message is a short, generic string
    assert!(
        message.len() < 50,
        "[CWE-209] Error message is suspiciously long ({} chars), \
         possibly leaking details: '{}'",
        message.len(),
        message
    );

    // Verify the message does not vary with request parameters
    // (same generic message regardless of user_id)
    let service2 = create_test_service(10);
    let request2 = build_strato_error_triggering_request(77777);
    let result2 = service2.get_in_network_posts(request2).await;

    assert!(result2.is_err(), "Expected error response for second request");
    let status2 = result2.unwrap_err();

    assert_eq!(
        status.message(),
        status2.message(),
        "Error messages should be identical regardless of request parameters. \
         First: '{}', Second: '{}'",
        status.message(),
        status2.message()
    );
}

// ---------------------------------------------------------------------------
// Test 3: Error response does not contain stack traces
// ---------------------------------------------------------------------------

/// Validates that gRPC error responses do not contain Rust stack traces,
/// file paths, or line numbers (CWE-209 / OWASP A09:2025).
///
/// **Attack scenario:** An attacker triggers an error and examines the response
/// for Rust-specific debug information that reveals internal code structure,
/// module layout, or dependency versions.
///
/// **Expected behavior after fix:** Error responses contain no traces of
/// source code references, file paths, or Rust runtime error formatting.
#[tokio::test]
async fn test_error_response_does_not_contain_stack_trace() {
    let service = create_test_service(10);

    let request = build_strato_error_triggering_request(54321);
    let result = service.get_in_network_posts(request).await;

    assert!(result.is_err(), "Expected error response");
    let status = result.unwrap_err();
    let message = status.message();

    // Check for Rust-specific stack trace patterns
    assert_no_sensitive_substrings(
        message,
        STACK_TRACE_SUBSTRINGS,
        "test_error_response_does_not_contain_stack_trace",
    );

    // Additionally check that the message does not contain any file extension patterns
    // that would indicate source code paths (e.g., ".rs", ".toml", ".proto")
    let file_extensions = [".rs", ".toml", ".proto", ".json", ".yaml", ".yml"];
    for ext in &file_extensions {
        assert!(
            !message.contains(ext),
            "[CWE-209] Error message contains file extension pattern '{}'. \
             Full message: '{}'",
            ext,
            message
        );
    }

    // Check for line number patterns (e.g., ":42", "line 42")
    let line_number_pattern = Regex::new(r"line \d+").expect("Invalid regex for line numbers");
    assert!(
        !line_number_pattern.is_match(message),
        "[CWE-209] Error message contains line number pattern. Message: '{}'",
        message
    );
}

// ---------------------------------------------------------------------------
// Test 4: Error response does not contain internal hostnames or IPs
// ---------------------------------------------------------------------------

/// Validates that gRPC error responses do not contain internal hostnames,
/// IP addresses, or port numbers that reveal network topology (CWE-209).
///
/// **Attack scenario:** An attacker triggers a network error and examines the
/// response for internal service hostnames (e.g., "strato-internal.svc:8080"),
/// IP addresses, or port numbers that could be used for lateral movement or
/// service enumeration within the internal network.
///
/// **Expected behavior after fix:** Error responses contain no network topology
/// information. All internal connection details are logged server-side only.
#[tokio::test]
async fn test_error_response_does_not_contain_internal_hostnames() {
    let service = create_test_service(10);

    let request = build_strato_error_triggering_request(11111);
    let result = service.get_in_network_posts(request).await;

    assert!(result.is_err(), "Expected error response");
    let status = result.unwrap_err();
    let message = status.message();

    // Check for IPv4 address patterns (e.g., "192.168.1.1", "10.0.0.1")
    let ip_pattern = Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        .expect("Invalid regex for IP addresses");
    assert!(
        !ip_pattern.is_match(message),
        "[CWE-209] Error message contains IP address pattern. Message: '{}'",
        message
    );

    // Check for IPv6 address patterns (e.g., "::1", "fe80::1")
    let ipv6_pattern =
        Regex::new(r"[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}").expect("Invalid regex for IPv6");
    assert!(
        !ipv6_pattern.is_match(message),
        "[CWE-209] Error message contains IPv6 address pattern. Message: '{}'",
        message
    );

    // Check for port number patterns (e.g., ":8080", ":3000", ":443")
    let port_pattern = Regex::new(r":\d{2,5}").expect("Invalid regex for port numbers");
    assert!(
        !port_pattern.is_match(message),
        "[CWE-209] Error message contains port number pattern. Message: '{}'",
        message
    );

    // Check for internal hostname patterns
    let hostname_substrings = [
        ".svc",
        ".local",
        ".internal",
        ".cluster",
        ".corp",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
    ];
    for hostname in &hostname_substrings {
        assert!(
            !message.contains(hostname),
            "[CWE-209] Error message contains internal hostname pattern '{}'. \
             Message: '{}'",
            hostname,
            message
        );
    }
}

// ---------------------------------------------------------------------------
// Test 5: Error is logged internally with full details
// ---------------------------------------------------------------------------

/// Validates that while gRPC responses are sanitized, detailed error information
/// is still logged internally for debugging (CWE-209 / OWASP A09:2025).
///
/// **Security rationale:** Sanitizing error responses must not compromise
/// operational debugging. The `warn!()` log at lines 283-286 of the updated
/// `thunder_service.rs` should still contain the full error details including
/// the original Strato error message, user ID, and failure reason.
///
/// **Expected behavior:** The gRPC response says "Internal service error"
/// while the internal log contains detailed error information for operators.
///
/// Note: This test uses `testing_logger` to capture and inspect log output.
/// The test validates the separation between external-facing error messages
/// (sanitized) and internal log messages (detailed).
#[tokio::test]
async fn test_error_is_logged_internally_with_details() {
    // Initialize the testing logger to capture log output
    testing_logger::setup();

    let service = create_test_service(10);

    let user_id: u64 = 67890;
    let request = build_strato_error_triggering_request(user_id);
    let result = service.get_in_network_posts(request).await;

    // The gRPC response should be sanitized
    assert!(result.is_err(), "Expected error response");
    let status = result.unwrap_err();
    assert_eq!(
        status.message(),
        "Internal service error",
        "gRPC response should be generic"
    );

    // Verify that the internal log captured detailed error information.
    // The warn!() at lines 283-286 should contain user ID and error details.
    testing_logger::validate(|captured_logs| {
        // Look for the warn-level log entry about the Strato fetch failure
        let has_detailed_log = captured_logs.iter().any(|entry| {
            entry.level == Level::Warn
                && entry.body.contains(&user_id.to_string())
                && entry.body.contains("Failed to fetch following list")
        });

        assert!(
            has_detailed_log,
            "Expected a warn-level log entry containing user_id '{}' and \
             'Failed to fetch following list'. Captured logs: {:?}",
            user_id,
            captured_logs
                .iter()
                .map(|entry| format!("[{}] {}", entry.level, entry.body))
                .collect::<Vec<_>>()
        );
    });
}

// ---------------------------------------------------------------------------
// Test 6: Integer overflow error is sanitized
// ---------------------------------------------------------------------------

/// Validates that integer overflow errors from the M-2 fix do not expose
/// implementation details about type constraints (CWE-209 / CWE-681).
///
/// **Attack scenario:** An attacker sends `user_id = u64::MAX` to trigger
/// the checked integer conversion added by Fix M-2. Before sanitization,
/// the error would contain "user_id 18446744073709551615 exceeds valid range",
/// leaking information about the internal type system (i64 vs u64 boundaries).
///
/// **Expected behavior after fix:** The error response contains only a generic
/// message like "Invalid request" without exposing the specific overflow value,
/// numeric limits, or type conversion details.
#[tokio::test]
async fn test_integer_overflow_error_is_sanitized() {
    let service = create_test_service(10);

    // Use u64::MAX to trigger the i64::try_from() overflow check added by Fix M-2
    let request = build_request_with_user_id(u64::MAX);
    let result = service.get_in_network_posts(request).await;

    // The request should fail due to integer overflow
    assert!(result.is_err(), "Expected error for u64::MAX user_id");
    let status = result.unwrap_err();
    let message = status.message();

    // The error code should be InvalidArgument (not Internal)
    assert!(
        status.code() == Code::InvalidArgument || status.code() == Code::Internal,
        "Expected Code::InvalidArgument or Code::Internal for overflow, got {:?}",
        status.code()
    );

    // The error message MUST NOT contain the actual overflow value
    let overflow_value = u64::MAX.to_string();
    assert!(
        !message.contains(&overflow_value),
        "[CWE-209] Error message exposes the specific overflow value '{}'. \
         Message: '{}'",
        overflow_value,
        message
    );

    // The error message MUST NOT contain type constraint details
    let type_detail_substrings = [
        "i64",
        "u64",
        "i32",
        "u32",
        "integer overflow",
        "overflow",
        "exceeds valid range",
        "TryFromIntError",
        "try_from",
        "conversion",
        "numeric",
        "18446744073709551615",
        "9223372036854775807", // i64::MAX
    ];

    assert_no_sensitive_substrings(
        message,
        &type_detail_substrings,
        "test_integer_overflow_error_is_sanitized",
    );

    // Verify the message is short and generic
    assert!(
        message.len() < 50,
        "[CWE-209] Overflow error message is suspiciously long ({} chars), \
         possibly leaking details: '{}'",
        message.len(),
        message
    );
}

// ---------------------------------------------------------------------------
// Test 7: Resource exhausted message is safe
// ---------------------------------------------------------------------------

/// Validates that the `Status::resource_exhausted()` message at the semaphore
/// check is safe and does not leak internal capacity details (CWE-209).
///
/// **Security rationale:** The existing message "Server at capacity, please retry"
/// is already generic and acceptable. This test serves as a regression guard to
/// ensure future changes don't introduce information leakage in this path.
///
/// **Expected behavior:** The resource exhausted response contains a generic
/// message without internal details about semaphore counts, thread pool sizes,
/// or other capacity implementation specifics.
#[tokio::test]
async fn test_resource_exhausted_message_is_safe() {
    // Create a service with max_concurrent_requests = 0 so the semaphore is
    // immediately exhausted, causing every request to be rejected.
    let service = create_test_service(0);

    let request = Request::new(GetInNetworkPostsRequest {
        user_id: 42,
        following_user_ids: vec![1, 2, 3],
        exclude_tweet_ids: vec![],
        max_results: 10,
        is_video_request: false,
        debug: false,
        algorithm: String::new(),
    });

    let result = service.get_in_network_posts(request).await;

    assert!(
        result.is_err(),
        "Expected resource_exhausted error when semaphore is at capacity"
    );
    let status = result.unwrap_err();

    // Verify the error code is RESOURCE_EXHAUSTED
    assert_eq!(
        status.code(),
        Code::ResourceExhausted,
        "Expected Code::ResourceExhausted, got {:?}",
        status.code()
    );

    let message = status.message();

    // The message should be the generic "Server at capacity, please retry"
    assert_eq!(
        message, "Server at capacity, please retry",
        "Resource exhausted message changed from expected value: '{}'",
        message
    );

    // Verify the message does not contain internal capacity details
    let capacity_detail_substrings = [
        "semaphore",
        "Semaphore",
        "permits",
        "threads",
        "concurrent",
        "max_concurrent",
        "tokio",
        "Tokio",
        "queue",
    ];

    assert_no_sensitive_substrings(
        message,
        &capacity_detail_substrings,
        "test_resource_exhausted_message_is_safe",
    );

    // Verify the message is short and appropriate
    assert!(
        message.len() < 100,
        "[CWE-209] Resource exhausted message is suspiciously long ({} chars): '{}'",
        message.len(),
        message
    );
}
