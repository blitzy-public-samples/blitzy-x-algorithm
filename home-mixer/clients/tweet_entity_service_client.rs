/// Tweet Entity Service (TES) client — internal API, excluded from open source release.
use crate::candidate_pipeline::candidate_features::{MediaEntities, PureCoreData};
use std::collections::HashMap;
use tonic::async_trait;

/// Trait defining the Tweet Entity Service interface for hydrating tweet data.
#[async_trait]
pub trait TESClient {
    /// Fetches core data (author, text, reply info) for a batch of tweet IDs.
    async fn get_tweet_core_datas(
        &self,
        tweet_ids: Vec<i64>,
    ) -> Result<HashMap<i64, Option<PureCoreData>>, Box<dyn std::error::Error + Send + Sync>>;

    /// Fetches media entities (video, photos) for a batch of tweet IDs.
    async fn get_tweet_media_entities(
        &self,
        tweet_ids: Vec<i64>,
    ) -> Result<HashMap<i64, Option<MediaEntities>>, Box<dyn std::error::Error + Send + Sync>>;

    /// Fetches subscription author IDs for a batch of tweet IDs.
    async fn get_subscription_author_ids(
        &self,
        tweet_ids: Vec<i64>,
    ) -> Result<HashMap<i64, Option<u64>>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Production TES client with gRPC connection.
pub struct ProdTESClient;

impl ProdTESClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self)
    }
}

#[async_trait]
impl TESClient for ProdTESClient {
    async fn get_tweet_core_datas(
        &self,
        _tweet_ids: Vec<i64>,
    ) -> Result<HashMap<i64, Option<PureCoreData>>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(HashMap::new())
    }

    async fn get_tweet_media_entities(
        &self,
        _tweet_ids: Vec<i64>,
    ) -> Result<HashMap<i64, Option<MediaEntities>>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(HashMap::new())
    }

    async fn get_subscription_author_ids(
        &self,
        _tweet_ids: Vec<i64>,
    ) -> Result<HashMap<i64, Option<u64>>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(HashMap::new())
    }
}
