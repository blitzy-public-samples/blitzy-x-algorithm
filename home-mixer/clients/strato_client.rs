/// Strato key-value store client — internal API, excluded from open source release.
use tonic::async_trait;

/// Trait defining the Strato key-value store interface.
#[async_trait]
pub trait StratoClient {
    /// Fetches user features from the Strato column store.
    async fn get_user_features(
        &self,
        user_id: i64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;

    /// Stores request info (which post IDs were served to a user) in Strato.
    async fn store_request_info(
        &self,
        user_id: i64,
        post_ids: Vec<i64>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Production Strato client.
pub struct ProdStratoClient;

impl ProdStratoClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self)
    }
}

#[async_trait]
impl StratoClient for ProdStratoClient {
    async fn get_user_features(
        &self,
        _user_id: i64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Production implementation connects to the internal Strato service
        Ok(Vec::new())
    }

    async fn store_request_info(
        &self,
        _user_id: i64,
        _post_ids: Vec<i64>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Production implementation connects to the internal Strato service
        Ok(Vec::new())
    }
}
