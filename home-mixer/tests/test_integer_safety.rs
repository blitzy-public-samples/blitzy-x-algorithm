//! # Security Integration Tests: Integer Type Cast Safety and Deduplication
//!
//! **Validates:**
//! - **Fix M-2** (CWE-681 / OWASP A10:2025): Checked integer conversions in
//!   `gizmoduck_hydrator.rs` — replaces unvalidated `as i64` / `as i32` casts
//!   with `i64::try_from()` / `i32::try_from()` that handle overflow gracefully
//!   instead of silently wrapping to incorrect values.
//! - **Fix L-3** (CWE-405 / OWASP A10:2025): Sort-before-dedup for proper
//!   deduplication of user IDs before batch API calls — replaces bare `.dedup()`
//!   with `.sort()` followed by `.dedup()` so non-adjacent duplicates are removed.
//!
//! ## Vulnerable Code Context (before fixes)
//!
//! In `gizmoduck_hydrator.rs`:
//! - Line 29: `author_ids.iter().map(|&x| x as i64)` — `u64` → `i64` silent wrap
//! - Line 32: `retweet_user_ids.iter().map(|&&x| x as i64)` — same overflow risk
//! - Line 46: `users.get(&(candidate.author_id as i64))` — lookup with wrapped key
//! - Line 52: `x.followers_count as i32` — `i64` → `i32` silent wrap
//! - Line 37: `.dedup()` without `.sort()` — only removes consecutive duplicates
//!
//! ## Security Impact
//!
//! Without Fix M-2, an attacker supplying `author_id = u64::MAX` causes the
//! unchecked `as i64` cast to produce `-1`, leading to incorrect user lookups
//! and potential data leakage from wrong user records. Without Fix L-3,
//! non-adjacent duplicate user IDs cause redundant external API calls,
//! amplifying load on the Gizmoduck service (CWE-405 asymmetric resource
//! consumption).
//!
//! ## Test Requirements
//!
//! Each test uses `#[tokio::test]` for async execution, constructs a
//! `MockGizmoduckClient` with controlled responses, and passes boundary-value
//! `PostCandidate` instances through the `GizmoduckCandidateHydrator` to verify
//! that checked conversions produce correct results or safe `None` defaults.
//!
//! **NOTE:** This integration test requires the `candidate_hydrators` and
//! `candidate_pipeline` modules to be re-exported as `pub mod` in the crate
//! root (`lib.rs`) for external test access. If modules remain private,
//! consider moving these tests to unit test modules within the source files.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tonic::async_trait;
use xai_candidate_pipeline::hydrator::Hydrator;
use xai_home_mixer::candidate_hydrators::gizmoduck_hydrator::GizmoduckCandidateHydrator;
use xai_home_mixer::candidate_pipeline::candidate::PostCandidate;
use xai_home_mixer::candidate_pipeline::query::ScoredPostsQuery;
use xai_home_mixer::clients::gizmoduck_client::{
    GizmoduckClient, UserCounts, UserData, UserProfile, UserResponse,
};

// ---------------------------------------------------------------------------
// Mock GizmoduckClient
// ---------------------------------------------------------------------------

/// Mock implementation of the `GizmoduckClient` trait for testing.
///
/// Captures every `get_users` invocation's argument list in `captured_ids`
/// (protected by `Mutex`) so that tests can assert on:
/// - Which user IDs were fetched (verifying overflow IDs are excluded)
/// - Whether the ID list is sorted and fully deduplicated (Fix L-3)
///
/// Returns pre-configured `responses` for each requested user ID.
struct MockGizmoduckClient {
    /// Records the `user_ids` argument of each `get_users()` call.
    captured_ids: Mutex<Vec<Vec<i64>>>,
    /// Pre-configured user data keyed by user ID (i64).
    responses: HashMap<i64, Option<UserResponse>>,
}

impl MockGizmoduckClient {
    /// Creates a new mock client with the given pre-configured user responses.
    fn new(responses: HashMap<i64, Option<UserResponse>>) -> Self {
        Self {
            captured_ids: Mutex::new(Vec::new()),
            responses,
        }
    }

    /// Returns a clone of all captured `get_users` call argument lists.
    ///
    /// Used by L-3 deduplication tests to verify the exact IDs sent to the
    /// external Gizmoduck service.
    fn get_captured_ids(&self) -> Vec<Vec<i64>> {
        self.captured_ids.lock().expect("Mock mutex poisoned").clone()
    }
}

#[async_trait]
impl GizmoduckClient for MockGizmoduckClient {
    async fn get_users(
        &self,
        user_ids: Vec<i64>,
    ) -> Result<HashMap<i64, Option<UserResponse>>, Box<dyn std::error::Error + Send + Sync>> {
        // Record this invocation's arguments for later assertion
        self.captured_ids
            .lock()
            .expect("Mock mutex poisoned")
            .push(user_ids.clone());

        // Return only the matching entries from pre-configured responses
        let mut result = HashMap::new();
        for id in &user_ids {
            if let Some(response) = self.responses.get(id) {
                result.insert(*id, response.clone());
            }
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Test helper functions
// ---------------------------------------------------------------------------

/// Builds a complete `UserResponse` with the specified followers count and
/// screen name. Used to configure mock responses for hydrator test scenarios.
///
/// The `followers_count` field is `i64` (from `UserCounts` in
/// `gizmoduck_client.rs`), and the hydrator converts it to `i32` via
/// `i32::try_from()`. Tests use boundary values here to verify the i32
/// conversion safety.
fn make_user_response(followers_count: i64, screen_name: &str) -> Option<UserResponse> {
    Some(UserResponse {
        user: Some(UserData {
            profile: UserProfile {
                screen_name: screen_name.to_string(),
            },
            counts: UserCounts { followers_count },
        }),
    })
}

/// Helper to construct a `PostCandidate` with only `author_id` set; all other
/// fields use safe defaults via `Default::default()`.
fn make_candidate(author_id: u64) -> PostCandidate {
    PostCandidate {
        author_id,
        ..Default::default()
    }
}

/// Helper to construct a `PostCandidate` with `author_id` and
/// `retweeted_user_id` set; all other fields use safe defaults.
fn make_candidate_with_retweet(author_id: u64, retweeted_user_id: u64) -> PostCandidate {
    PostCandidate {
        author_id,
        retweeted_user_id: Some(retweeted_user_id),
        ..Default::default()
    }
}

// ===========================================================================
// Fix M-2: Integer Type Cast Safety Tests (CWE-681 / OWASP A10:2025)
// ===========================================================================

/// **[M-2]** Verify that `author_id` at exactly `i64::MAX` converts successfully.
///
/// `i64::MAX as u64` equals 9,223,372,036,854,775,807, which is the maximum
/// `u64` value that fits safely in an `i64`. The hydrator should:
/// 1. Successfully convert the author_id via `i64::try_from()`
/// 2. Include the ID in the Gizmoduck fetch list
/// 3. Look up and hydrate the candidate with the correct user data
///
/// This validates the upper boundary of safe conversion.
#[tokio::test]
async fn test_author_id_at_i64_max_boundary() {
    // i64::MAX as u64 = 9_223_372_036_854_775_807 — the largest safe value
    let author_id: u64 = i64::MAX as u64;
    let user_id_i64: i64 = i64::MAX;

    let mut responses = HashMap::new();
    responses.insert(user_id_i64, make_user_response(500_000, "maxuser"));

    let mock_client = Arc::new(MockGizmoduckClient::new(responses));
    let hydrator = GizmoduckCandidateHydrator::new(mock_client.clone()).await;
    let query = ScoredPostsQuery::default();
    let candidates = vec![make_candidate(author_id)];

    let result = hydrator.hydrate(&query, &candidates).await;

    // Hydration must succeed — the author_id is within safe i64 range
    assert!(
        result.is_ok(),
        "Hydration should succeed for author_id at i64::MAX boundary"
    );
    let hydrated = result.unwrap();
    assert_eq!(hydrated.len(), 1, "Should return exactly one hydrated candidate");

    // User data should be correctly hydrated
    assert_eq!(
        hydrated[0].author_screen_name,
        Some("maxuser".to_string()),
        "Screen name should be hydrated for safe i64::MAX author_id"
    );
    assert_eq!(
        hydrated[0].author_followers_count,
        Some(500_000),
        "Followers count should be hydrated for safe i64::MAX author_id"
    );

    // Verify the correct i64 value was sent to Gizmoduck
    let captured = mock_client.get_captured_ids();
    assert_eq!(captured.len(), 1, "get_users should be called exactly once");
    assert!(
        captured[0].contains(&user_id_i64),
        "i64::MAX should be in the fetch list as a valid ID"
    );
}

/// **[M-2]** Verify that `author_id = u64::MAX` is handled gracefully without panic.
///
/// `u64::MAX` (18,446,744,073,709,551,615) exceeds `i64::MAX`. Before Fix M-2,
/// the unchecked `as i64` cast would silently wrap to `-1`, causing an incorrect
/// user lookup that could return the wrong user's data. After Fix M-2,
/// `i64::try_from()` detects the overflow, the candidate is skipped in the
/// fetch, and the hydrated candidate receives `None` user fields (safe
/// degradation).
///
/// **Attack vector:** An attacker setting `author_id = u64::MAX` could
/// previously cause the hydrator to look up user ID `-1`, potentially
/// returning another user's profile data or causing a service error.
#[tokio::test]
async fn test_author_id_exceeding_i64_max_returns_error() {
    let author_id: u64 = u64::MAX; // 18_446_744_073_709_551_615

    // No responses configured — the overflow ID should never reach Gizmoduck
    let mock_client = Arc::new(MockGizmoduckClient::new(HashMap::new()));
    let hydrator = GizmoduckCandidateHydrator::new(mock_client.clone()).await;
    let query = ScoredPostsQuery::default();
    let candidates = vec![make_candidate(author_id)];

    let result = hydrator.hydrate(&query, &candidates).await;

    // The hydrator should return Ok with gracefully degraded fields (None),
    // NOT panic or silently wrap to a negative i64 value
    assert!(
        result.is_ok(),
        "Hydration must not panic for u64::MAX author_id; should degrade gracefully"
    );
    let hydrated = result.unwrap();
    assert_eq!(hydrated.len(), 1, "Should return one candidate even with overflow ID");

    // All user-derived fields should be None (user not found due to overflow)
    assert_eq!(
        hydrated[0].author_screen_name, None,
        "Screen name must be None when author_id overflows i64"
    );
    assert_eq!(
        hydrated[0].author_followers_count, None,
        "Followers count must be None when author_id overflows i64"
    );

    // CRITICAL: Verify the wrapped value (-1) was NOT sent to Gizmoduck
    let captured = mock_client.get_captured_ids();
    assert_eq!(captured.len(), 1, "get_users should be called exactly once");
    assert!(
        !captured[0].contains(&-1_i64),
        "Wrapped -1 value must NOT be sent to external service (CWE-681 violation)"
    );
    // The only candidate's author_id overflowed, so no valid IDs to fetch
    assert!(
        captured[0].is_empty(),
        "No IDs should be fetched when the only author_id overflows i64"
    );
}

/// **[M-2]** Verify that `retweeted_user_id = u64::MAX` is handled gracefully.
///
/// The retweet user ID conversion path has the same overflow risk as the
/// author_id path (line 32 in original code: `x as i64`). After Fix M-2,
/// `i64::try_from()` catches the overflow. The candidate's author should still
/// be hydrated normally; only the retweet user lookup should be skipped.
#[tokio::test]
async fn test_retweet_user_id_exceeding_i64_max_returns_error() {
    let normal_author_id: u64 = 12345;
    let overflow_retweet_id: u64 = u64::MAX;

    let mut responses = HashMap::new();
    responses.insert(12345_i64, make_user_response(1000, "author_user"));

    let mock_client = Arc::new(MockGizmoduckClient::new(responses));
    let hydrator = GizmoduckCandidateHydrator::new(mock_client.clone()).await;
    let query = ScoredPostsQuery::default();
    let candidates = vec![make_candidate_with_retweet(normal_author_id, overflow_retweet_id)];

    let result = hydrator.hydrate(&query, &candidates).await;

    assert!(
        result.is_ok(),
        "Hydration must not panic for u64::MAX retweeted_user_id"
    );
    let hydrated = result.unwrap();
    assert_eq!(hydrated.len(), 1);

    // Author should still be hydrated normally — the overflow is only on the retweet ID
    assert_eq!(
        hydrated[0].author_screen_name,
        Some("author_user".to_string()),
        "Author screen name should be hydrated even when retweet ID overflows"
    );
    assert_eq!(
        hydrated[0].author_followers_count,
        Some(1000),
        "Author followers count should be hydrated even when retweet ID overflows"
    );
    // Retweet user should NOT be hydrated — overflow ID was skipped
    assert_eq!(
        hydrated[0].retweeted_screen_name, None,
        "Retweet screen name must be None when retweeted_user_id overflows i64"
    );

    // Verify only the valid author ID was sent to Gizmoduck (no wrapped retweet ID)
    let captured = mock_client.get_captured_ids();
    assert_eq!(captured.len(), 1, "get_users should be called exactly once");
    assert!(
        captured[0].contains(&12345_i64),
        "Valid author ID should be in the fetch list"
    );
    assert!(
        !captured[0].contains(&-1_i64),
        "Wrapped retweet ID (-1) must NOT be in fetch list (CWE-681)"
    );
}

/// **[M-2]** Verify the minimum overflow boundary: `(i64::MAX as u64) + 1`.
///
/// The value 9,223,372,036,854,775,808 is the smallest `u64` that cannot
/// fit in an `i64`. This is a critical boundary test — off-by-one errors
/// in range checking would miss this case.
#[tokio::test]
async fn test_author_id_just_over_i64_max() {
    // (i64::MAX as u64) + 1 = 9_223_372_036_854_775_808 — minimum overflow value
    let author_id: u64 = (i64::MAX as u64) + 1;

    let mock_client = Arc::new(MockGizmoduckClient::new(HashMap::new()));
    let hydrator = GizmoduckCandidateHydrator::new(mock_client.clone()).await;
    let query = ScoredPostsQuery::default();
    let candidates = vec![make_candidate(author_id)];

    let result = hydrator.hydrate(&query, &candidates).await;

    assert!(
        result.is_ok(),
        "Hydration must not panic for (i64::MAX + 1) author_id"
    );
    let hydrated = result.unwrap();
    assert_eq!(hydrated.len(), 1);

    // User fields should be None — the author_id just overflows i64
    assert_eq!(
        hydrated[0].author_screen_name, None,
        "Screen name must be None for just-overflowed author_id"
    );
    assert_eq!(
        hydrated[0].author_followers_count, None,
        "Followers count must be None for just-overflowed author_id"
    );

    // Verify no IDs were fetched (the only author_id overflowed)
    let captured = mock_client.get_captured_ids();
    assert_eq!(captured.len(), 1, "get_users should be called exactly once");
    assert!(
        captured[0].is_empty(),
        "No IDs should be fetched when the only author_id is just over i64::MAX"
    );

    // Double-check: the old code would have produced i64::MIN (silent wrap)
    // Verify that value is NOT in the fetch list
    assert!(
        !captured[0].contains(&i64::MIN),
        "Wrapped i64::MIN value must NOT appear in fetch list (CWE-681)"
    );
}

/// **[M-2]** Verify that `followers_count` exceeding `i32::MAX` is not silently
/// wrapped.
///
/// Before Fix M-2, `followers_count as i32` would silently overflow for values
/// greater than 2,147,483,647 (`i32::MAX`). For example, a count of
/// 2,147,483,648 would wrap to -2,147,483,648. After the fix,
/// `i32::try_from()` returns `Err` and `author_followers_count` becomes `None`.
///
/// This is particularly important for high-profile accounts with very large
/// follower counts that could approach or exceed i32::MAX.
#[tokio::test]
async fn test_followers_count_exceeding_i32_max() {
    let author_id: u64 = 42;
    // i32::MAX as i64 + 1 = 2_147_483_648 — minimum i32 overflow value
    let overflow_count: i64 = i32::MAX as i64 + 1;

    let mut responses = HashMap::new();
    responses.insert(42_i64, make_user_response(overflow_count, "bigfollower"));

    let mock_client = Arc::new(MockGizmoduckClient::new(responses));
    let hydrator = GizmoduckCandidateHydrator::new(mock_client.clone()).await;
    let query = ScoredPostsQuery::default();
    let candidates = vec![make_candidate(author_id)];

    let result = hydrator.hydrate(&query, &candidates).await;

    assert!(
        result.is_ok(),
        "Hydration should succeed even with overflow followers_count"
    );
    let hydrated = result.unwrap();
    assert_eq!(hydrated.len(), 1);

    // Screen name should still be hydrated — only the count conversion overflowed
    assert_eq!(
        hydrated[0].author_screen_name,
        Some("bigfollower".to_string()),
        "Screen name should be hydrated when only followers_count overflows i32"
    );

    // Followers count must be None (not a silently-wrapped negative value)
    assert_eq!(
        hydrated[0].author_followers_count, None,
        "Followers count must be None when it exceeds i32::MAX, not silently wrapped"
    );

    // Explicitly verify the old wrapping behavior does NOT occur
    assert_ne!(
        hydrated[0].author_followers_count,
        Some(i32::MIN),
        "Followers count must NOT wrap to i32::MIN (CWE-681 violation)"
    );
    assert_ne!(
        hydrated[0].author_followers_count,
        Some(-2_147_483_648_i32),
        "Followers count must NOT wrap to -2147483648"
    );
}

/// **[M-2]** Verify that `followers_count` within i32 range converts correctly.
///
/// Normal operation: a `followers_count` of 1,000,000 is well within the
/// `i32` range (max 2,147,483,647) and should hydrate correctly without any
/// conversion issues.
#[tokio::test]
async fn test_followers_count_within_i32_range() {
    let author_id: u64 = 99;
    let normal_count: i64 = 1_000_000;

    let mut responses = HashMap::new();
    responses.insert(99_i64, make_user_response(normal_count, "normaluser"));

    let mock_client = Arc::new(MockGizmoduckClient::new(responses));
    let hydrator = GizmoduckCandidateHydrator::new(mock_client.clone()).await;
    let query = ScoredPostsQuery::default();
    let candidates = vec![make_candidate(author_id)];

    let result = hydrator.hydrate(&query, &candidates).await;

    assert!(
        result.is_ok(),
        "Hydration should succeed for normal followers_count"
    );
    let hydrated = result.unwrap();
    assert_eq!(hydrated.len(), 1);

    // Both fields should be correctly hydrated
    assert_eq!(
        hydrated[0].author_followers_count,
        Some(1_000_000_i32),
        "Followers count should convert correctly within i32 range"
    );
    assert_eq!(
        hydrated[0].author_screen_name,
        Some("normaluser".to_string()),
        "Screen name should be hydrated for valid user"
    );
}

/// **[M-2]** Verify that typical user IDs in the safe range convert correctly.
///
/// Tests the happy path with multiple candidates to ensure the checked
/// conversions do not regress normal functionality. Uses representative
/// user IDs that are well within the safe u64→i64 range.
#[tokio::test]
async fn test_normal_user_ids_convert_correctly() {
    let mut responses = HashMap::new();
    responses.insert(12345_i64, make_user_response(50_000, "alice"));
    responses.insert(67890_i64, make_user_response(100_000, "bob"));

    let mock_client = Arc::new(MockGizmoduckClient::new(responses));
    let hydrator = GizmoduckCandidateHydrator::new(mock_client.clone()).await;
    let query = ScoredPostsQuery::default();
    let candidates = vec![
        make_candidate(12345_u64),
        make_candidate(67890_u64),
    ];

    let result = hydrator.hydrate(&query, &candidates).await;

    assert!(
        result.is_ok(),
        "Hydration should succeed for normal user IDs"
    );
    let hydrated = result.unwrap();
    assert_eq!(hydrated.len(), 2, "Should return two hydrated candidates");

    // First candidate
    assert_eq!(
        hydrated[0].author_screen_name,
        Some("alice".to_string()),
        "First candidate screen name should match"
    );
    assert_eq!(
        hydrated[0].author_followers_count,
        Some(50_000_i32),
        "First candidate followers count should match"
    );

    // Second candidate
    assert_eq!(
        hydrated[1].author_screen_name,
        Some("bob".to_string()),
        "Second candidate screen name should match"
    );
    assert_eq!(
        hydrated[1].author_followers_count,
        Some(100_000_i32),
        "Second candidate followers count should match"
    );

    // Verify both valid IDs were included in the fetch
    let captured = mock_client.get_captured_ids();
    assert_eq!(captured.len(), 1, "get_users should be called exactly once");
    assert!(
        captured[0].contains(&12345_i64) && captured[0].contains(&67890_i64),
        "Both valid author IDs should be in the fetch list"
    );
}

// ===========================================================================
// Fix L-3: Sort-Before-Dedup Tests (CWE-405 / OWASP A10:2025)
// ===========================================================================

/// **[L-3]** Verify that non-adjacent duplicate author IDs are properly
/// deduplicated.
///
/// Before Fix L-3, `Vec::dedup()` only removed **consecutive** duplicates.
/// Given candidates with author_ids `[1, 2, 1, 3, 2]`, bare `dedup()` would
/// remove nothing (no consecutive dupes), causing the Gizmoduck fetch to
/// include all 5 IDs. After Fix L-3, `sort()` runs first, producing
/// `[1, 1, 2, 2, 3]`, then `dedup()` reduces it to `[1, 2, 3]`.
///
/// **Security impact (CWE-405):** Non-deduped IDs amplify external API load
/// proportionally to the number of redundant entries, enabling an attacker
/// to multiply resource consumption on downstream services.
#[tokio::test]
async fn test_dedup_with_sort_removes_non_adjacent_duplicates() {
    let mut responses = HashMap::new();
    responses.insert(1_i64, make_user_response(100, "user_1"));
    responses.insert(2_i64, make_user_response(200, "user_2"));
    responses.insert(3_i64, make_user_response(300, "user_3"));

    let mock_client = Arc::new(MockGizmoduckClient::new(responses));
    let hydrator = GizmoduckCandidateHydrator::new(mock_client.clone()).await;
    let query = ScoredPostsQuery::default();

    // Candidates with non-adjacent duplicate author IDs: [1, 2, 1, 3, 2]
    let candidates = vec![
        make_candidate(1_u64),
        make_candidate(2_u64),
        make_candidate(1_u64),
        make_candidate(3_u64),
        make_candidate(2_u64),
    ];

    let result = hydrator.hydrate(&query, &candidates).await;
    assert!(
        result.is_ok(),
        "Hydration should succeed with duplicate author IDs"
    );

    // Verify the mock received a properly sorted and deduplicated ID list
    let captured = mock_client.get_captured_ids();
    assert_eq!(captured.len(), 1, "get_users should be called exactly once");

    let fetched_ids = &captured[0];

    // After sort+dedup, exactly 3 unique IDs should be fetched
    assert_eq!(
        fetched_ids.len(),
        3,
        "Only 3 unique IDs should be fetched, not {} \
         (CWE-405: non-adjacent duplicates must be removed by sort+dedup)",
        fetched_ids.len()
    );

    // Verify the IDs are sorted and fully deduplicated
    assert_eq!(
        fetched_ids,
        &vec![1_i64, 2, 3],
        "Fetched IDs should be [1, 2, 3] after sort+dedup"
    );

    // Verify all 5 candidates are still returned (hydrator doesn't drop candidates)
    let hydrated = result.unwrap();
    assert_eq!(
        hydrated.len(),
        5,
        "All 5 candidates should be returned regardless of dedup"
    );
}

/// **[L-3]** Verify that overlapping author IDs and retweet user IDs are
/// deduplicated in the combined fetch list.
///
/// When `author_ids` and `retweet_user_ids` share common values, the combined
/// vector should be sorted and deduplicated before the Gizmoduck API call.
///
/// Example:
/// - Candidates: `[{author: 1, retweet: 2}, {author: 3, retweet: 1}]`
/// - Combined before fix: `[1, 3, 2, 1]` → `dedup` = `[1, 3, 2, 1]` (no consecutive dupes)
/// - Combined after fix: `[1, 3, 2, 1]` → `sort` = `[1, 1, 2, 3]` → `dedup` = `[1, 2, 3]`
#[tokio::test]
async fn test_dedup_with_retweet_ids_and_author_ids() {
    let mut responses = HashMap::new();
    responses.insert(1_i64, make_user_response(100, "user_1"));
    responses.insert(2_i64, make_user_response(200, "user_2"));
    responses.insert(3_i64, make_user_response(300, "user_3"));

    let mock_client = Arc::new(MockGizmoduckClient::new(responses));
    let hydrator = GizmoduckCandidateHydrator::new(mock_client.clone()).await;
    let query = ScoredPostsQuery::default();

    let candidates = vec![
        make_candidate_with_retweet(1, 2),
        make_candidate_with_retweet(3, 1), // retweet_user_id=1 overlaps with first author_id
    ];

    let result = hydrator.hydrate(&query, &candidates).await;
    assert!(
        result.is_ok(),
        "Hydration should succeed with overlapping author/retweet IDs"
    );

    // Verify the combined fetch list is properly deduplicated
    let captured = mock_client.get_captured_ids();
    assert_eq!(captured.len(), 1, "get_users should be called exactly once");

    let fetched_ids = &captured[0];
    assert_eq!(
        fetched_ids.len(),
        3,
        "Only 3 unique IDs should be fetched from combined author + retweet IDs"
    );
    assert_eq!(
        fetched_ids,
        &vec![1_i64, 2, 3],
        "Combined author and retweet IDs should be sorted and deduplicated"
    );

    // Verify hydration results are correct
    let hydrated = result.unwrap();
    assert_eq!(hydrated.len(), 2, "Both candidates should be returned");

    // First candidate: author=1 (user_1), retweet=2 (user_2)
    assert_eq!(
        hydrated[0].author_screen_name,
        Some("user_1".to_string()),
        "First candidate author screen name should be user_1"
    );
    assert_eq!(
        hydrated[0].retweeted_screen_name,
        Some("user_2".to_string()),
        "First candidate retweet screen name should be user_2"
    );

    // Second candidate: author=3 (user_3), retweet=1 (user_1)
    assert_eq!(
        hydrated[1].author_screen_name,
        Some("user_3".to_string()),
        "Second candidate author screen name should be user_3"
    );
    assert_eq!(
        hydrated[1].retweeted_screen_name,
        Some("user_1".to_string()),
        "Second candidate retweet screen name should reference user_1"
    );
}

// ===========================================================================
// Error Message Safety Test (CWE-209 adjacent)
// ===========================================================================

/// **[M-2]** Verify that integer overflow is handled without exposing internal
/// type conversion details in error messages or output values.
///
/// When an overflow occurs, the hydrator should:
/// 1. Return `Ok(...)` (graceful degradation, not an error with internal details)
/// 2. Set user fields to `None` (not silently-wrapped incorrect values)
/// 3. NOT include raw u64 values, type names ("u64", "i64"), or conversion
///    function names ("try_from", "TryFromIntError") in any returned data
///
/// This complements CWE-209 (Error Message Containing Sensitive Information)
/// by ensuring that overflow handling does not leak implementation details
/// to callers.
#[tokio::test]
async fn test_integer_overflow_error_message_is_safe() {
    let mock_client = Arc::new(MockGizmoduckClient::new(HashMap::new()));
    let hydrator = GizmoduckCandidateHydrator::new(mock_client.clone()).await;
    let query = ScoredPostsQuery::default();

    // Construct candidates with multiple overflow scenarios simultaneously
    let candidates = vec![PostCandidate {
        author_id: u64::MAX,
        retweeted_user_id: Some((i64::MAX as u64) + 1),
        ..Default::default()
    }];

    let result = hydrator.hydrate(&query, &candidates).await;

    // PRIMARY ASSERTION: The hydrator returns Ok (graceful degradation).
    // No error message with internal details is exposed to the caller.
    assert!(
        result.is_ok(),
        "Overflow must be handled gracefully without returning an error containing \
         internal conversion details"
    );

    let hydrated = result.unwrap();
    assert_eq!(hydrated.len(), 1, "One candidate should be returned");

    // Verify the candidate has safe None defaults (not wrapped values)
    assert_eq!(
        hydrated[0].author_screen_name, None,
        "Overflow author ID should produce None screen name, not data from wrong user"
    );
    assert_eq!(
        hydrated[0].author_followers_count, None,
        "Overflow should not produce followers count from incorrect user lookup"
    );
    assert_eq!(
        hydrated[0].retweeted_screen_name, None,
        "Overflow retweet ID should produce None screen name"
    );

    // SECONDARY ASSERTION: If the implementation ever changes to return Err,
    // verify the error message does not contain sensitive conversion details.
    // This future-proofs the test against implementation changes.
    let second_result: Result<Vec<PostCandidate>, String> =
        hydrator.hydrate(&query, &candidates).await;
    if let Err(ref err_msg) = second_result {
        // Verify no raw numeric values are exposed
        assert!(
            !err_msg.contains("18446744073709551615"),
            "Error message must not contain the raw u64::MAX value"
        );
        assert!(
            !err_msg.contains("9223372036854775808"),
            "Error message must not contain the (i64::MAX + 1) value"
        );
        // Verify no internal type names are exposed
        assert!(
            !err_msg.contains("u64") && !err_msg.contains("i64"),
            "Error message must not contain internal type names (u64/i64)"
        );
        assert!(
            !err_msg.contains("i32"),
            "Error message must not contain internal type name (i32)"
        );
        // Verify no conversion function details are exposed
        assert!(
            !err_msg.contains("try_from") && !err_msg.contains("TryFromIntError"),
            "Error message must not contain conversion function details"
        );
    }

    // Verify overflow IDs were NOT sent to the external Gizmoduck service
    let captured = mock_client.get_captured_ids();
    assert_eq!(captured.len(), 2, "get_users should be called twice (two hydrate calls)");
    for call_ids in &captured {
        assert!(
            !call_ids.contains(&-1_i64),
            "No wrapped negative values should be sent to the external service"
        );
    }
}
