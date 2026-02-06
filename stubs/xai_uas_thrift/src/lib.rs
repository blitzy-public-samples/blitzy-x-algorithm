// =============================================================================
// xai_uas_thrift — Stub for User Action Sequence thrift types and conversion.
// =============================================================================

pub mod user_action_sequence {
    /// A thrift-format aggregated user action.
    #[derive(Debug, Clone, Default)]
    pub struct AggregatedUserAction {
        pub tweet_id: Option<u64>,
        pub action_type: Option<i32>,
        pub count: Option<u64>,
        pub impressed_time_ms: Option<i64>,
    }

    /// Metadata for a user action sequence in thrift format.
    #[derive(Debug, Clone, Default)]
    pub struct UserActionSequenceMeta {
        pub length: Option<i64>,
        pub last_modified_epoch_ms: Option<i64>,
        pub last_kafka_publish_epoch_ms: Option<i64>,
    }

    /// A user action sequence in thrift format.
    #[derive(Debug, Clone, Default)]
    pub struct UserActionSequence {
        pub user_id: Option<i64>,
        pub metadata: Option<UserActionSequenceMeta>,
        pub user_actions: Option<Vec<AggregatedUserAction>>,
    }
}

pub mod convert {
    use super::user_action_sequence::AggregatedUserAction as ThriftAction;
    use xai_recsys_proto::AggregatedUserAction as ProtoAction;

    /// Converts a thrift AggregatedUserAction to its proto equivalent.
    pub fn thrift_to_proto_aggregated_user_action(
        thrift: ThriftAction,
    ) -> Result<ProtoAction, String> {
        Ok(ProtoAction {
            tweet_id: thrift.tweet_id.unwrap_or(0),
            action_type: thrift.action_type.unwrap_or(0),
            count: thrift.count.unwrap_or(0),
            impressed_time_ms: thrift.impressed_time_ms.unwrap_or(0) as u64,
        })
    }
}
