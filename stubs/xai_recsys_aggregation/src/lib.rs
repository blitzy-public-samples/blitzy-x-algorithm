// =============================================================================
// xai_recsys_aggregation — Stub for user action aggregation logic.
// =============================================================================

pub mod aggregation {
    use xai_uas_thrift::user_action_sequence::AggregatedUserAction;

    /// Trait for aggregating user actions.
    pub trait UserActionAggregator: Send + Sync {
        fn run(
            &self,
            actions: &[AggregatedUserAction],
            window_time_ms: u64,
            min_count: u64,
        ) -> Vec<AggregatedUserAction>;

        fn name(&self) -> &str;
    }

    /// Default aggregator implementation that passes through actions.
    pub struct DefaultAggregator;

    impl UserActionAggregator for DefaultAggregator {
        fn run(
            &self,
            actions: &[AggregatedUserAction],
            _window_time_ms: u64,
            _min_count: u64,
        ) -> Vec<AggregatedUserAction> {
            actions.to_vec()
        }

        fn name(&self) -> &str {
            "DefaultAggregator"
        }
    }
}

pub mod filters {
    use xai_uas_thrift::user_action_sequence::AggregatedUserAction;

    /// Filter applied to individual user actions before aggregation.
    pub trait UserActionFilter: Send + Sync {
        fn run(&self, actions: Vec<AggregatedUserAction>) -> Vec<AggregatedUserAction>;
    }

    /// Filter applied to aggregated user actions after aggregation.
    pub trait AggregatedActionFilter: Send + Sync {
        fn run(&self, actions: Vec<AggregatedUserAction>) -> Vec<AggregatedUserAction>;
    }

    /// Keeps only original (non-synthetic) user actions.
    pub struct KeepOriginalUserActionFilter;

    impl KeepOriginalUserActionFilter {
        pub fn new() -> Self {
            Self
        }
    }

    impl UserActionFilter for KeepOriginalUserActionFilter {
        fn run(&self, actions: Vec<AggregatedUserAction>) -> Vec<AggregatedUserAction> {
            actions
        }
    }

    /// Filters aggregated actions to keep only dense entries.
    pub struct DenseAggregatedActionFilter;

    impl DenseAggregatedActionFilter {
        pub fn new() -> Self {
            Self
        }
    }

    impl AggregatedActionFilter for DenseAggregatedActionFilter {
        fn run(&self, actions: Vec<AggregatedUserAction>) -> Vec<AggregatedUserAction> {
            actions
        }
    }
}
