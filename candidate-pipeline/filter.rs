use std::any::{Any, type_name_of_val};
use tonic::async_trait;

use crate::util;

pub struct FilterResult<C> {
    pub kept: Vec<C>,
    pub removed: Vec<C>,
}

/// Filters run sequentially and partition candidates into kept and removed sets
#[async_trait]
pub trait Filter<Q, C>: Any + Send + Sync
where
    Q: Clone + Send + Sync + 'static,
    C: Clone + Send + Sync + 'static,
{
    /// Decide if this filter should run for the given query
    fn enable(&self, _query: &Q) -> bool {
        true
    }

    /// Indicates whether this filter is safety-critical.
    /// Safety-critical filters (e.g., visibility/content safety filters) will
    /// cause ALL candidates to be dropped if the filter fails (fail-closed behavior).
    /// Non-safety-critical filters retain the default fail-open behavior where
    /// candidates are restored from a pre-filter backup on error.
    /// Override this to return `true` for content safety, visibility filtering,
    /// or other filters where bypassing the filter on error would be a security risk.
    fn is_safety_critical(&self) -> bool {
        false
    }

    /// Filter candidates by evaluating each against some criteria.
    /// Returns a FilterResult containing kept candidates (which continue to the next stage)
    /// and removed candidates (which are excluded from further processing).
    async fn filter(&self, query: &Q, candidates: Vec<C>) -> Result<FilterResult<C>, String>;

    /// Returns a stable name for logging/metrics.
    fn name(&self) -> &'static str {
        util::short_type_name(type_name_of_val(self))
    }
}
