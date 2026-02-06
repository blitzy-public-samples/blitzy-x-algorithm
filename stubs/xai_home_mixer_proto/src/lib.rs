// =============================================================================
// xai_home_mixer_proto — Stub crate for Home Mixer gRPC protobuf types.
//
// Provides the generated protobuf types and gRPC service definitions that the
// home-mixer crate depends on. In production, these types are generated from
// .proto files by prost/tonic; here we supply minimal hand-written stubs for
// local development and testing.
// =============================================================================

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::{Request, Response, Status};

// ── Encoded File Descriptor Set ─────────────────────────────────────────────
// Used by tonic_reflection for gRPC reflection. Stub provides an empty slice.
pub const FILE_DESCRIPTOR_SET: &[u8] = &[];

// ── ServedType Enum ─────────────────────────────────────────────────────────

/// Enum representing how a post was sourced for the timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(i32)]
pub enum ServedType {
    #[default]
    Unknown = 0,
    ForYouInNetwork = 1,
    ForYouPhoenixRetrieval = 2,
}

// ── ImpressionBloomFilterEntry ──────────────────────────────────────────────

/// Entry representing a bloom filter element for impression deduplication.
#[derive(Debug, Clone, Default)]
pub struct ImpressionBloomFilterEntry {
    pub bloom_filter_hash: u64,
    pub served_timestamp_ms: u64,
    pub filter_data: Vec<u8>,
    pub num_hashes: u32,
}

// ── VisibilityReason ────────────────────────────────────────────────────────

/// Visibility filtering reason as a protobuf-compatible message.
/// Mirrors the proto VisibilityReason message, convertible from the internal
/// xai_visibility_filtering::models::FilteredReason enum.
#[derive(Debug, Clone, Default)]
pub struct VisibilityReason {
    pub reason_code: i32,
    pub description: String,
}

impl From<xai_visibility_filtering::models::FilteredReason> for VisibilityReason {
    fn from(reason: xai_visibility_filtering::models::FilteredReason) -> Self {
        match reason {
            xai_visibility_filtering::models::FilteredReason::SafetyResult(sr) => {
                VisibilityReason {
                    reason_code: 1,
                    description: format!("{:?}", sr.action),
                }
            }
            xai_visibility_filtering::models::FilteredReason::Other(s) => VisibilityReason {
                reason_code: 0,
                description: s,
            },
        }
    }
}

// ── ScoredPostsQuery (Request) ──────────────────────────────────────────────

/// gRPC request message for the GetScoredPosts RPC.
#[derive(Debug, Clone, Default)]
pub struct ScoredPostsQuery {
    pub viewer_id: i64,
    pub client_app_id: i32,
    pub country_code: String,
    pub language_code: String,
    pub seen_ids: Vec<i64>,
    pub served_ids: Vec<i64>,
    pub in_network_only: bool,
    pub is_bottom_request: bool,
    pub bloom_filter_entries: Vec<ImpressionBloomFilterEntry>,
    pub auth_token: String,
}

// ── ScoredPost (Response item) ──────────────────────────────────────────────

/// A single scored post in the response.
#[derive(Debug, Clone, Default)]
pub struct ScoredPost {
    pub tweet_id: u64,
    pub author_id: u64,
    pub retweeted_tweet_id: u64,
    pub retweeted_user_id: u64,
    pub in_reply_to_tweet_id: u64,
    pub score: f32,
    pub in_network: bool,
    pub served_type: i32,
    pub last_scored_timestamp_ms: u64,
    pub prediction_request_id: u64,
    pub ancestors: Vec<u64>,
    pub screen_names: HashMap<u64, String>,
    pub visibility_reason: Option<VisibilityReason>,
}

// ── ScoredPostsResponse ─────────────────────────────────────────────────────

/// gRPC response message for the GetScoredPosts RPC.
#[derive(Debug, Clone, Default)]
pub struct ScoredPostsResponse {
    pub scored_posts: Vec<ScoredPost>,
}

// ── gRPC Server Definitions ─────────────────────────────────────────────────

pub mod scored_posts_service_server {
    use super::*;

    /// Async trait for the ScoredPosts gRPC service.
    #[tonic::async_trait]
    pub trait ScoredPostsService: Send + Sync + 'static {
        async fn get_scored_posts(
            &self,
            request: Request<ScoredPostsQuery>,
        ) -> Result<Response<ScoredPostsResponse>, Status>;
    }

    /// gRPC server wrapper for ScoredPostsService implementations.
    ///
    /// Mirrors the tonic-generated server by implementing:
    /// - `tower::Service<http::Request<tonic::body::BoxBody>>`
    /// - `tonic::server::NamedService`
    /// - `Clone`
    #[derive(Debug, Clone)]
    pub struct ScoredPostsServiceServer<T: ScoredPostsService> {
        inner: T,
    }

    impl<T: ScoredPostsService> ScoredPostsServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }

        pub fn max_decoding_message_size(self, _size: usize) -> Self {
            self
        }

        pub fn max_encoding_message_size(self, _size: usize) -> Self {
            self
        }

        pub fn accept_compressed(
            self,
            _encoding: tonic::codec::CompressionEncoding,
        ) -> Self {
            self
        }

        pub fn send_compressed(
            self,
            _encoding: tonic::codec::CompressionEncoding,
        ) -> Self {
            self
        }

        /// Get a reference to the inner service.
        pub fn inner(&self) -> &T {
            &self.inner
        }
    }

    // Implement tower::Service for ScoredPostsServiceServer (required for routing).
    impl<T: ScoredPostsService + Clone> tower::Service<http::Request<tonic::body::BoxBody>>
        for ScoredPostsServiceServer<T>
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future =
            Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<tonic::body::BoxBody>) -> Self::Future {
            Box::pin(async {
                Ok(http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(tonic::body::empty_body())
                    .unwrap())
            })
        }
    }

    // Implement NamedService for ScoredPostsServiceServer (required for gRPC routing).
    impl<T: ScoredPostsService> tonic::server::NamedService
        for ScoredPostsServiceServer<T>
    {
        const NAME: &'static str = "home_mixer.ScoredPostsService";
    }
}

// ── gRPC Client Definitions ─────────────────────────────────────────────────

pub mod scored_posts_service_client {
    use super::*;
    use tonic::transport::Channel;

    /// gRPC client for the ScoredPosts service.
    #[derive(Debug, Clone)]
    pub struct ScoredPostsServiceClient<T> {
        inner: T,
    }

    impl ScoredPostsServiceClient<Channel> {
        pub fn new(channel: Channel) -> Self {
            Self { inner: channel }
        }

        pub async fn get_scored_posts(
            &mut self,
            request: Request<ScoredPostsQuery>,
        ) -> Result<Response<ScoredPostsResponse>, Status> {
            let _ = request;
            Err(Status::unimplemented("Stub client — use tonic transport"))
        }
    }
}
