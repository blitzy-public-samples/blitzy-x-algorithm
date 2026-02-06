//! Stub crate for xai_thunder_proto — provides protobuf-generated types and gRPC service
//! definitions for Thunder's in-network posts service. This is a minimal stub sufficient
//! for compilation and testing of the security fixes.

use tonic::{Request, Response, Status};

// -----------------------------------------------------------------------
// Protobuf message types
// -----------------------------------------------------------------------

/// Lightweight representation of a post, used for in-memory caching and gRPC responses.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LightPost {
    pub post_id: i64,
    pub author_id: i64,
    pub created_at: i64,
    pub is_reply: bool,
    pub is_retweet: bool,
    pub has_video: bool,
    pub source_post_id: Option<i64>,
    pub source_user_id: Option<i64>,
    pub in_reply_to_post_id: Option<i64>,
    pub in_reply_to_user_id: Option<i64>,
    pub conversation_id: Option<i64>,
}

impl Default for LightPost {
    fn default() -> Self {
        Self {
            post_id: 0,
            author_id: 0,
            created_at: 0,
            is_reply: false,
            is_retweet: false,
            has_video: false,
            source_post_id: None,
            source_user_id: None,
            in_reply_to_post_id: None,
            in_reply_to_user_id: None,
            conversation_id: None,
        }
    }
}

/// Kafka proto event for tweet creation (v2 format — non-optional scalar fields).
#[derive(Debug, Clone, Default)]
pub struct TweetCreateEvent {
    pub post_id: i64,
    pub author_id: i64,
    pub created_at: i64,
    pub is_reply: bool,
    pub is_retweet: bool,
    pub has_video: bool,
    pub source_post_id: Option<i64>,
    pub source_user_id: Option<i64>,
    pub in_reply_to_post_id: Option<i64>,
    pub in_reply_to_user_id: Option<i64>,
    pub conversation_id: Option<i64>,
}

/// Kafka proto event for tweet deletion.
#[derive(Debug, Clone, Default)]
pub struct TweetDeleteEvent {
    pub post_id: i64,
    pub deleted_at: i64,
}

/// Wrapper for in-network Kafka events (proto v2 format).
#[derive(Debug, Clone, Default)]
pub struct InNetworkEvent {
    pub event_variant: Option<in_network_event::EventVariant>,
}

/// Sub-module for in_network_event variants, matching protobuf oneof pattern.
pub mod in_network_event {
    use super::*;

    #[derive(Debug, Clone)]
    pub enum EventVariant {
        TweetCreateEvent(TweetCreateEvent),
        TweetDeleteEvent(TweetDeleteEvent),
    }
}

impl prost::Message for InNetworkEvent {
    fn encode_raw(&self, _buf: &mut impl prost::bytes::BufMut) {}

    fn merge_field(
        &mut self,
        _tag: u32,
        _wire_type: prost::encoding::WireType,
        _buf: &mut impl prost::bytes::Buf,
        _ctx: prost::encoding::DecodeContext,
    ) -> Result<(), prost::DecodeError> {
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        0
    }

    fn clear(&mut self) {
        self.event_variant = None;
    }
}

// -----------------------------------------------------------------------
// gRPC request/response types
// -----------------------------------------------------------------------

/// Request message for the GetInNetworkPosts RPC.
#[derive(Debug, Clone, Default)]
pub struct GetInNetworkPostsRequest {
    pub user_id: u64,
    pub following_user_ids: Vec<u64>,
    pub exclude_tweet_ids: Vec<u64>,
    pub max_results: u32,
    pub is_video_request: bool,
    pub debug: bool,
    pub algorithm: String,
}

/// Response message for the GetInNetworkPosts RPC.
#[derive(Debug, Clone, Default)]
pub struct GetInNetworkPostsResponse {
    pub posts: Vec<LightPost>,
}

// -----------------------------------------------------------------------
// gRPC server definitions
// -----------------------------------------------------------------------

pub mod in_network_posts_service_server {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Async trait for the InNetworkPosts gRPC service.
    #[tonic::async_trait]
    pub trait InNetworkPostsService: Send + Sync + 'static {
        async fn get_in_network_posts(
            &self,
            request: Request<GetInNetworkPostsRequest>,
        ) -> Result<Response<GetInNetworkPostsResponse>, Status>;
    }

    /// gRPC server wrapper for InNetworkPostsService implementations.
    ///
    /// This stub mirrors the tonic-generated server by implementing:
    /// - `tower::Service<http::Request<tonic::body::BoxBody>>` (required for routing)
    /// - `tonic::server::NamedService` (required for `Routes::new()`)
    /// - `Clone` (required for concurrent request handling)
    #[derive(Debug, Clone)]
    pub struct InNetworkPostsServiceServer<T: InNetworkPostsService> {
        inner: T,
    }

    impl<T: InNetworkPostsService> InNetworkPostsServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
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

        /// Wrap this server with an interceptor for authentication, logging, etc.
        pub fn with_interceptor<F>(
            self,
            interceptor: F,
        ) -> CustomInterceptedService<T, F>
        where
            F: tonic::service::Interceptor,
        {
            CustomInterceptedService {
                inner: self.inner,
                interceptor,
            }
        }

        /// Get a reference to the inner service.
        pub fn inner(&self) -> &T {
            &self.inner
        }
    }

    // --- Implement tower::Service for InNetworkPostsServiceServer ---
    // This is required so that tonic::service::interceptor::InterceptedService
    // and tonic::service::Routes can wrap and compose this server type.
    impl<T: InNetworkPostsService + Clone> tower::Service<http::Request<tonic::body::BoxBody>>
        for InNetworkPostsServiceServer<T>
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future =
            Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<tonic::body::BoxBody>) -> Self::Future {
            // Stub: return an empty gRPC response. In production, tonic-generated
            // code routes through the proto codec and dispatches to the trait impl.
            Box::pin(async {
                Ok(http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(tonic::body::empty_body())
                    .unwrap())
            })
        }
    }

    // --- Implement NamedService for InNetworkPostsServiceServer ---
    // Required by tonic::service::Routes::new() for gRPC routing.
    impl<T: InNetworkPostsService> tonic::server::NamedService
        for InNetworkPostsServiceServer<T>
    {
        const NAME: &'static str = "thunder.InNetworkPostsService";
    }

    /// A custom intercepted service wrapper that applies authentication/validation
    /// before dispatching to the inner service.
    #[derive(Debug, Clone)]
    pub struct CustomInterceptedService<T: InNetworkPostsService, F: tonic::service::Interceptor> {
        inner: T,
        interceptor: F,
    }

    impl<T: InNetworkPostsService, F: tonic::service::Interceptor>
        CustomInterceptedService<T, F>
    {
        /// Execute a request through the interceptor and then the service.
        ///
        /// The interceptor receives a `Request<()>` (metadata only) per tonic convention.
        /// If it succeeds, the typed request is forwarded to the inner service.
        pub async fn call_get_in_network_posts(
            &mut self,
            request: Request<GetInNetworkPostsRequest>,
        ) -> Result<Response<GetInNetworkPostsResponse>, Status> {
            // Build a metadata-only request for the interceptor
            let (metadata, extensions, message) = request.into_parts();
            let mut interceptor_req = Request::new(());
            *interceptor_req.metadata_mut() = metadata.clone();
            *interceptor_req.extensions_mut() = extensions.clone();

            // Run the interceptor — if it rejects, propagate the error
            let _checked = self.interceptor.call(interceptor_req)?;

            // Reconstruct the typed request and dispatch to the inner service
            let mut typed_req = Request::new(message);
            *typed_req.metadata_mut() = metadata;
            *typed_req.extensions_mut() = extensions;
            self.inner.get_in_network_posts(typed_req).await
        }

        /// Get a reference to the inner service.
        pub fn inner(&self) -> &T {
            &self.inner
        }
    }
}

// -----------------------------------------------------------------------
// gRPC client definitions
// -----------------------------------------------------------------------

pub mod in_network_posts_service_client {
    use super::*;
    use tonic::transport::Channel;

    /// gRPC client for the InNetworkPosts service.
    #[derive(Debug, Clone)]
    pub struct InNetworkPostsServiceClient<T> {
        inner: T,
    }

    impl InNetworkPostsServiceClient<Channel> {
        pub fn new(channel: Channel) -> Self {
            Self { inner: channel }
        }

        pub async fn get_in_network_posts(
            &mut self,
            request: Request<GetInNetworkPostsRequest>,
        ) -> Result<Response<GetInNetworkPostsResponse>, Status> {
            let _ = request;
            Err(Status::unimplemented("Stub client — use tonic transport"))
        }
    }
}
