/// User Action Sequence fetcher — internal API, excluded from open source release.
use tonic::async_trait;
use xai_uas_thrift::user_action_sequence::UserActionSequence as ThriftUserActionSequence;

/// Trait defining operations for fetching user action sequences.
#[async_trait]
pub trait UserActionSequenceOps: Send + Sync {
    /// Fetches the user action sequence for a given user ID.
    async fn get_by_user_id(
        &self,
        user_id: i64,
    ) -> Result<ThriftUserActionSequence, Box<dyn std::error::Error + Send + Sync>>;
}

/// Fetcher for retrieving user action sequences from the UAS store.
pub struct UserActionSequenceFetcher;

impl UserActionSequenceFetcher {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self)
    }
}

#[async_trait]
impl UserActionSequenceOps for UserActionSequenceFetcher {
    async fn get_by_user_id(
        &self,
        _user_id: i64,
    ) -> Result<ThriftUserActionSequence, Box<dyn std::error::Error + Send + Sync>> {
        // Production implementation fetches from the UAS store
        Ok(ThriftUserActionSequence::default())
    }
}
