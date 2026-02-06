/// Phoenix ML prediction client — internal API, excluded from open source release.
use tonic::async_trait;
use xai_recsys_proto::{PredictNextActionsResponse, TweetInfo, UserActionSequence};

/// Trait defining the Phoenix prediction service interface.
#[async_trait]
pub trait PhoenixPredictionClient {
    /// Sends a prediction request to the Phoenix ML model.
    async fn predict(
        &self,
        user_id: u64,
        user_action_sequence: UserActionSequence,
        tweet_infos: Vec<TweetInfo>,
    ) -> Result<PredictNextActionsResponse, Box<dyn std::error::Error + Send + Sync>>;
}

/// Production Phoenix prediction client with gRPC connection.
pub struct ProdPhoenixPredictionClient;

impl ProdPhoenixPredictionClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self)
    }
}

#[async_trait]
impl PhoenixPredictionClient for ProdPhoenixPredictionClient {
    async fn predict(
        &self,
        _user_id: u64,
        _user_action_sequence: UserActionSequence,
        _tweet_infos: Vec<TweetInfo>,
    ) -> Result<PredictNextActionsResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Production implementation connects to the internal Phoenix service
        Ok(PredictNextActionsResponse::default())
    }
}
