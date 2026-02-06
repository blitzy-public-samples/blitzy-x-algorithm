// =============================================================================
// xai_twittercontext_proto — Stub for Twitter context protobuf types.
// =============================================================================

/// Twitter context viewer information extracted from request metadata.
#[derive(Debug, Clone, Default)]
pub struct TwitterContextViewer {
    pub user_id: i64,
    pub client_application_id: i64,
    pub request_country_code: String,
    pub request_language_code: String,
}

/// Trait for types that can provide a Twitter context viewer.
pub trait GetTwitterContextViewer {
    fn get_viewer(&self) -> Option<TwitterContextViewer>;
}
