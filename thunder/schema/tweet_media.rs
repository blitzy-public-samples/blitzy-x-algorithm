//! Tweet media schema definitions.

/// Video information for a media attachment.
#[derive(Debug, Clone, Default)]
pub struct VideoInfo {
    /// Video duration in milliseconds, if known.
    pub duration_millis: Option<i64>,
}

/// Describes the specific media type.
#[derive(Debug, Clone)]
pub enum MediaInfo {
    /// The media is a video.
    VideoInfo(VideoInfo),
    /// The media is a photo.
    PhotoInfo,
    /// The media is an animated GIF.
    AnimatedGifInfo,
}

/// A single media entity attached to a tweet.
#[derive(Debug, Clone)]
pub struct MediaEntity {
    /// Type-specific media information.
    pub media_info: Option<MediaInfo>,
}

impl Default for MediaEntity {
    fn default() -> Self {
        Self { media_info: None }
    }
}
