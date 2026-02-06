use clap::Parser;
use log::info;
use std::time::Duration;

use tonic::codec::CompressionEncoding;
use tonic::service::RoutesBuilder;
use tonic_reflection::server::Builder;

use xai_home_mixer_proto as pb;
use xai_http_server::{CancellationToken, GrpcConfig, HttpServer};

use xai_home_mixer::params;
use xai_home_mixer::HomeMixerServer;

#[derive(Parser, Debug)]
#[command(about = "HomeMixer gRPC Server")]
struct Args {
    #[arg(long)]
    grpc_port: u16,
    #[arg(long)]
    metrics_port: u16,
    #[arg(long)]
    reload_interval_minutes: u64,
    #[arg(long)]
    chunk_size: usize,
}

#[xai_stats_macro::main(name = "home-mixer")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    xai_init_utils::init().log();
    xai_init_utils::init().rustls();
    info!(
        "Starting server with gRPC port: {}, metrics port: {}, reload interval: {} minutes, chunk size: {}",
        args.grpc_port, args.metrics_port, args.reload_interval_minutes, args.chunk_size,
    );

    // Create the service implementation
    let service = HomeMixerServer::new().await;

    let mut grpc_routes = RoutesBuilder::default();

    grpc_routes.add_service(
        pb::scored_posts_service_server::ScoredPostsServiceServer::new(service)
            .max_decoding_message_size(params::MAX_GRPC_MESSAGE_SIZE)
            .max_encoding_message_size(params::MAX_GRPC_MESSAGE_SIZE)
            .accept_compressed(CompressionEncoding::Gzip)
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Gzip)
            .send_compressed(CompressionEncoding::Zstd),
    );

    // [L-2] Security Fix (CWE-489 / OWASP A02:2025): Gate gRPC reflection
    // behind the ENABLE_GRPC_REFLECTION environment variable. gRPC reflection
    // exposes the complete service schema to any client, enabling service
    // enumeration. In production this should be disabled.
    let enable_reflection = std::env::var("ENABLE_GRPC_REFLECTION")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");
    if enable_reflection {
        let reflection_service = Builder::configure()
            .register_encoded_file_descriptor_set(pb::FILE_DESCRIPTOR_SET)
            .build_v1()?;
        grpc_routes.add_service(reflection_service);
        info!("gRPC reflection enabled via ENABLE_GRPC_REFLECTION");
    } else {
        info!("gRPC reflection disabled (set ENABLE_GRPC_REFLECTION=true to enable)");
    }

    let grpc_config = GrpcConfig::new(args.grpc_port, grpc_routes.routes());

    let http_router = axum::Router::default();

    let mut server = HttpServer::new(
        args.metrics_port,
        http_router,
        Some(grpc_config),
        CancellationToken::new(),
        Duration::from_secs(20),
    )
    .await?;

    server.set_readiness(true);
    info!("Server ready");
    server.wait_for_termination().await;
    info!("Server shutdown complete");
    Ok(())
}
