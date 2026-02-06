/// Gizmoduck user lookup client — internal API, excluded from open source release.
use std::collections::HashMap;
use tonic::async_trait;

/// User profile data returned by the Gizmoduck service.
#[derive(Debug, Clone, Default)]
pub struct UserProfile {
    pub screen_name: String,
}

/// User counts (followers, following, etc.) returned by Gizmoduck.
#[derive(Debug, Clone, Default)]
pub struct UserCounts {
    pub followers_count: i64,
}

/// Inner user data containing profile and counts.
#[derive(Debug, Clone, Default)]
pub struct UserData {
    pub profile: UserProfile,
    pub counts: UserCounts,
}

/// Full user response from Gizmoduck containing optional user data.
#[derive(Debug, Clone, Default)]
pub struct UserResponse {
    pub user: Option<UserData>,
}

/// Trait defining the Gizmoduck user lookup interface.
#[async_trait]
pub trait GizmoduckClient {
    /// Fetches user data for the given user IDs.
    /// Returns a map from user ID to optional user response.
    async fn get_users(
        &self,
        user_ids: Vec<i64>,
    ) -> Result<HashMap<i64, Option<UserResponse>>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Production Gizmoduck client that connects to the real user service.
pub struct ProdGizmoduckClient;

impl ProdGizmoduckClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self)
    }
}

#[async_trait]
impl GizmoduckClient for ProdGizmoduckClient {
    async fn get_users(
        &self,
        _user_ids: Vec<i64>,
    ) -> Result<HashMap<i64, Option<UserResponse>>, Box<dyn std::error::Error + Send + Sync>> {
        // Production implementation connects to the internal Gizmoduck service
        Ok(HashMap::new())
    }
}
