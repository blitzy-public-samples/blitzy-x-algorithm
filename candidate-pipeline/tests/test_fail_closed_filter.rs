//! Integration tests for the H-4 security fix: fail-closed content safety filter behavior.
//!
//! **CWE-636** (Not Failing Securely) / **OWASP A04:2025** (Cryptographic/Safety Failures)
//!
//! Validates that the `run_filters()` error handling in `CandidatePipeline` correctly
//! distinguishes between safety-critical and non-critical filters:
//!
//! - **Safety-critical filters** that return `Err` cause ALL candidates to be dropped
//!   (fail-closed), preventing unfiltered content from being served when a safety
//!   service (e.g., Visibility Filtering) is unavailable.
//! - **Non-critical filters** that return `Err` restore candidates from a pre-filter
//!   backup (fail-open), preserving backward-compatible behavior for non-safety filters.
//!
//! Without these tests, there would be no automated verification that the content safety
//! bypass vulnerability (CWE-636) is properly remediated by the H-4 fix.

use std::sync::Arc;

use candidate_pipeline::candidate_pipeline::{CandidatePipeline, HasRequestId};
use candidate_pipeline::filter::{Filter, FilterResult};
use candidate_pipeline::hydrator::Hydrator;
use candidate_pipeline::query_hydrator::QueryHydrator;
use candidate_pipeline::scorer::Scorer;
use candidate_pipeline::selector::Selector;
use candidate_pipeline::side_effect::SideEffect;
use candidate_pipeline::source::Source;
use tonic::async_trait;

// ---------------------------------------------------------------------------
// Test Types — minimal types satisfying all CandidatePipeline trait bounds
// ---------------------------------------------------------------------------

/// Minimal query type carrying only a request identifier for logging/tracing.
/// Satisfies the `HasRequestId + Clone + Send + Sync + 'static` bounds required
/// by `CandidatePipeline<Q, C>`.
#[derive(Clone, Debug)]
struct TestQuery {
    request_id: String,
}

impl HasRequestId for TestQuery {
    fn request_id(&self) -> &str {
        &self.request_id
    }
}

/// Minimal candidate type with a unique `id` field for identity verification.
/// Satisfies the `Clone + Send + Sync + 'static` bounds required by
/// `CandidatePipeline<Q, C>`, plus `PartialEq + Debug` for test assertions.
#[derive(Clone, Debug, PartialEq)]
struct TestCandidate {
    id: u64,
}

// ---------------------------------------------------------------------------
// Mock Filter Implementations — exercise both fail-closed and fail-open paths
// ---------------------------------------------------------------------------

/// A safety-critical filter that always returns `Err`, simulating a VF (Visibility
/// Filtering) service failure. When `is_safety_critical()` returns `true` and
/// `filter()` returns `Err`, the H-4 fix in `run_filters()` must drop ALL
/// candidates (fail-closed behavior) to prevent serving unfiltered content.
struct SafetyCriticalFailingFilter;

#[async_trait]
impl Filter<TestQuery, TestCandidate> for SafetyCriticalFailingFilter {
    fn enable(&self, _query: &TestQuery) -> bool {
        true
    }

    /// Override the default `false` to mark this filter as safety-critical.
    /// This is the core mechanism tested by H-4: safety-critical filters
    /// trigger fail-closed error handling in `run_filters()`.
    fn is_safety_critical(&self) -> bool {
        true
    }

    async fn filter(
        &self,
        _query: &TestQuery,
        _candidates: Vec<TestCandidate>,
    ) -> Result<FilterResult<TestCandidate>, String> {
        Err("VF service unavailable".to_string())
    }
}

/// A non-critical filter that always returns `Err`. Inherits the default
/// `is_safety_critical() -> false` from the `Filter` trait. When this filter
/// errors, `run_filters()` must restore candidates from the pre-filter backup
/// (fail-open behavior), preserving backward compatibility.
struct NonCriticalFailingFilter;

#[async_trait]
impl Filter<TestQuery, TestCandidate> for NonCriticalFailingFilter {
    fn enable(&self, _query: &TestQuery) -> bool {
        true
    }

    // Deliberately does NOT override is_safety_critical(), inheriting default `false`.

    async fn filter(
        &self,
        _query: &TestQuery,
        _candidates: Vec<TestCandidate>,
    ) -> Result<FilterResult<TestCandidate>, String> {
        Err("non-critical filter error".to_string())
    }
}

/// A filter that passes all candidates through without modification.
/// Used as a baseline to verify normal filter flow and to test sequential
/// filter execution alongside failing filters.
struct PassthroughFilter;

#[async_trait]
impl Filter<TestQuery, TestCandidate> for PassthroughFilter {
    fn enable(&self, _query: &TestQuery) -> bool {
        true
    }

    async fn filter(
        &self,
        _query: &TestQuery,
        candidates: Vec<TestCandidate>,
    ) -> Result<FilterResult<TestCandidate>, String> {
        Ok(FilterResult {
            kept: candidates,
            removed: vec![],
        })
    }
}

/// A safety-critical filter that succeeds (returns `Ok` with all candidates kept).
/// Validates that the safety-critical code path does NOT accidentally drop
/// candidates when the filter operates successfully — only errors should
/// trigger the fail-closed behavior.
struct SafetyCriticalSucceedingFilter;

#[async_trait]
impl Filter<TestQuery, TestCandidate> for SafetyCriticalSucceedingFilter {
    fn enable(&self, _query: &TestQuery) -> bool {
        true
    }

    fn is_safety_critical(&self) -> bool {
        true
    }

    async fn filter(
        &self,
        _query: &TestQuery,
        candidates: Vec<TestCandidate>,
    ) -> Result<FilterResult<TestCandidate>, String> {
        Ok(FilterResult {
            kept: candidates,
            removed: vec![],
        })
    }
}

// ---------------------------------------------------------------------------
// Mock Source — provides a fixed set of test candidates
// ---------------------------------------------------------------------------

/// A source that returns a pre-configured vector of test candidates.
/// Satisfies the `Source<Q, C>` trait with `Any + Send + Sync` bounds.
struct MockSource {
    candidates: Vec<TestCandidate>,
}

impl MockSource {
    fn new(candidates: Vec<TestCandidate>) -> Self {
        Self { candidates }
    }
}

#[async_trait]
impl Source<TestQuery, TestCandidate> for MockSource {
    async fn get_candidates(
        &self,
        _query: &TestQuery,
    ) -> Result<Vec<TestCandidate>, String> {
        Ok(self.candidates.clone())
    }
}

// ---------------------------------------------------------------------------
// Mock Selector — disabled to preserve filter output for assertion
// ---------------------------------------------------------------------------

/// A selector that is always disabled, causing the pipeline's `select()` step
/// to return candidates as-is. This ensures filter results are directly
/// observable in `PipelineResult::selected_candidates` without interference
/// from sorting or truncation.
struct MockSelector;

impl Selector<TestQuery, TestCandidate> for MockSelector {
    fn enable(&self, _query: &TestQuery) -> bool {
        false
    }

    fn score(&self, _candidate: &TestCandidate) -> f64 {
        0.0
    }
}

// ---------------------------------------------------------------------------
// Test Pipeline — configurable CandidatePipeline implementation for testing
// ---------------------------------------------------------------------------

/// A minimal `CandidatePipeline` implementation that allows per-test configuration
/// of filters while providing empty/no-op implementations for all other pipeline
/// stages. This isolates the filter error handling behavior under test.
struct TestPipeline {
    sources: Vec<Box<dyn Source<TestQuery, TestCandidate>>>,
    filters: Vec<Box<dyn Filter<TestQuery, TestCandidate>>>,
    selector: MockSelector,
    query_hydrators: Vec<Box<dyn QueryHydrator<TestQuery>>>,
    hydrators: Vec<Box<dyn Hydrator<TestQuery, TestCandidate>>>,
    scorers: Vec<Box<dyn Scorer<TestQuery, TestCandidate>>>,
    post_selection_hydrators: Vec<Box<dyn Hydrator<TestQuery, TestCandidate>>>,
    post_selection_filters: Vec<Box<dyn Filter<TestQuery, TestCandidate>>>,
    side_effects: Arc<Vec<Box<dyn SideEffect<TestQuery, TestCandidate>>>>,
}

#[async_trait]
impl CandidatePipeline<TestQuery, TestCandidate> for TestPipeline {
    fn query_hydrators(&self) -> &[Box<dyn QueryHydrator<TestQuery>>] {
        &self.query_hydrators
    }

    fn sources(&self) -> &[Box<dyn Source<TestQuery, TestCandidate>>] {
        &self.sources
    }

    fn hydrators(&self) -> &[Box<dyn Hydrator<TestQuery, TestCandidate>>] {
        &self.hydrators
    }

    fn filters(&self) -> &[Box<dyn Filter<TestQuery, TestCandidate>>] {
        &self.filters
    }

    fn scorers(&self) -> &[Box<dyn Scorer<TestQuery, TestCandidate>>] {
        &self.scorers
    }

    fn selector(&self) -> &dyn Selector<TestQuery, TestCandidate> {
        &self.selector
    }

    fn post_selection_hydrators(&self) -> &[Box<dyn Hydrator<TestQuery, TestCandidate>>] {
        &self.post_selection_hydrators
    }

    fn post_selection_filters(&self) -> &[Box<dyn Filter<TestQuery, TestCandidate>>] {
        &self.post_selection_filters
    }

    fn side_effects(&self) -> Arc<Vec<Box<dyn SideEffect<TestQuery, TestCandidate>>>> {
        self.side_effects.clone()
    }

    fn result_size(&self) -> usize {
        100
    }
}

// ---------------------------------------------------------------------------
// Helper Functions — reduce boilerplate across test cases
// ---------------------------------------------------------------------------

/// Creates a fixed set of 3 test candidates for consistent assertions.
/// The candidate count (3) is greater than 0, ensuring that both fail-closed
/// (empty result) and fail-open (full restore) behaviors are distinguishable.
fn test_candidates() -> Vec<TestCandidate> {
    vec![
        TestCandidate { id: 1 },
        TestCandidate { id: 2 },
        TestCandidate { id: 3 },
    ]
}

/// Creates a test query with a stable request identifier for logging consistency.
fn test_query() -> TestQuery {
    TestQuery {
        request_id: "test-h4-security-validation".to_string(),
    }
}

/// Builds a `TestPipeline` with the given filters and standard test infrastructure.
/// Sources provide `test_candidates()`, selector is disabled, and all other stages
/// are empty/no-op to isolate filter behavior.
fn build_pipeline(
    filters: Vec<Box<dyn Filter<TestQuery, TestCandidate>>>,
) -> TestPipeline {
    TestPipeline {
        sources: vec![Box::new(MockSource::new(test_candidates()))],
        filters,
        selector: MockSelector,
        query_hydrators: vec![],
        hydrators: vec![],
        scorers: vec![],
        post_selection_hydrators: vec![],
        post_selection_filters: vec![],
        side_effects: Arc::new(vec![]),
    }
}

// ---------------------------------------------------------------------------
// Test Cases — H-4 security fix validation
// ---------------------------------------------------------------------------

/// **[H-4 PRIMARY SECURITY VALIDATION]** Safety-critical filter failure must drop
/// ALL candidates (fail-closed behavior).
///
/// This is the most important test in this module. It validates that when a
/// safety-critical filter (e.g., Visibility Filtering) fails with an `Err`,
/// the `run_filters()` method drops all candidates to zero — preventing
/// unfiltered content from being served to users.
///
/// **Attack scenario:** VF service goes down → safety filter returns Err →
/// WITHOUT the H-4 fix, candidates are restored from backup (fail-open) →
/// unfiltered/unsafe content is served to users (CWE-636 bypass).
///
/// **Expected with H-4 fix:** Zero candidates survive → no content served →
/// safety-over-availability trade-off honored.
#[tokio::test]
async fn test_safety_critical_filter_error_drops_all_candidates() {
    let pipeline = build_pipeline(vec![
        Box::new(SafetyCriticalFailingFilter),
    ]);

    let result = pipeline.execute(test_query()).await;

    assert!(
        result.selected_candidates.is_empty(),
        "SECURITY VIOLATION (CWE-636): Safety-critical filter failure must drop ALL candidates \
         (fail-closed), but {} candidates survived. The content safety bypass is still present.",
        result.selected_candidates.len()
    );
}

/// **[H-4 Backward Compatibility]** Non-critical filter failure must restore
/// candidates from the pre-filter backup (fail-open behavior).
///
/// This validates that the H-4 fix does NOT break existing behavior for
/// non-safety-critical filters. When a non-critical filter fails, the original
/// fail-open semantics must be preserved: candidates are restored from the
/// backup taken before the filter ran.
#[tokio::test]
async fn test_non_critical_filter_error_restores_backup() {
    let expected_count = test_candidates().len();
    let pipeline = build_pipeline(vec![
        Box::new(NonCriticalFailingFilter),
    ]);

    let result = pipeline.execute(test_query()).await;

    assert_eq!(
        result.selected_candidates.len(),
        expected_count,
        "Non-critical filter failure should restore all {} candidates from backup (fail-open), \
         but got {} candidates instead.",
        expected_count,
        result.selected_candidates.len()
    );
}

/// **[H-4 Success Path]** A safety-critical filter that succeeds must pass
/// candidates through normally.
///
/// This validates that the fail-closed code path does NOT accidentally drop
/// candidates when the safety filter operates without error. Only `Err` returns
/// from safety-critical filters should trigger the candidate drop — `Ok` returns
/// must behave identically to non-critical filter success.
#[tokio::test]
async fn test_safety_critical_filter_success_passes_candidates() {
    let expected_count = test_candidates().len();
    let pipeline = build_pipeline(vec![
        Box::new(SafetyCriticalSucceedingFilter),
    ]);

    let result = pipeline.execute(test_query()).await;

    assert_eq!(
        result.selected_candidates.len(),
        expected_count,
        "Safety-critical filter that succeeds should pass all {} candidates through, \
         but got {} candidates. The success path must not trigger fail-closed behavior.",
        expected_count,
        result.selected_candidates.len()
    );
}

/// **[H-4 Sequential Execution]** Safety-critical failure after a successful
/// non-critical filter must still drop ALL candidates.
///
/// Tests the sequential filter execution path: `PassthroughFilter` succeeds
/// (all candidates pass through), then `SafetyCriticalFailingFilter` fails.
/// Even though the first filter succeeded, the safety-critical failure in the
/// second filter must drop ALL remaining candidates to zero.
///
/// This validates that safety-critical fail-closed behavior applies regardless
/// of prior filter results in the chain.
#[tokio::test]
async fn test_mixed_filters_safety_critical_failure_after_non_critical() {
    let pipeline = build_pipeline(vec![
        Box::new(PassthroughFilter),
        Box::new(SafetyCriticalFailingFilter),
    ]);

    let result = pipeline.execute(test_query()).await;

    assert!(
        result.selected_candidates.is_empty(),
        "Safety-critical filter failure after a successful passthrough filter must still drop \
         ALL candidates (fail-closed), but {} candidates survived.",
        result.selected_candidates.len()
    );
}

/// **[H-4 Sequential Execution]** Non-critical failure before a successful
/// filter must restore backup and allow subsequent filters to proceed.
///
/// Tests sequential filter execution: `NonCriticalFailingFilter` fails
/// (candidates restored from backup via fail-open), then `PassthroughFilter`
/// succeeds (all restored candidates pass through). The final result should
/// contain all original candidates.
///
/// This validates that fail-open restore does not corrupt the candidate list
/// for subsequent filters in the chain.
#[tokio::test]
async fn test_mixed_filters_non_critical_failure_before_safety_critical() {
    let expected_count = test_candidates().len();
    let pipeline = build_pipeline(vec![
        Box::new(NonCriticalFailingFilter),
        Box::new(PassthroughFilter),
    ]);

    let result = pipeline.execute(test_query()).await;

    assert_eq!(
        result.selected_candidates.len(),
        expected_count,
        "Non-critical filter failure (fail-open) followed by passthrough should result in \
         all {} candidates, but got {}. Backup restore may have corrupted the candidate list.",
        expected_count,
        result.selected_candidates.len()
    );
}
