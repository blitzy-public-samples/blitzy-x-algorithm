/// Request utility functions — excluded from open source release for security reasons.
use uuid::Uuid;

/// Generates a unique request ID string for tracing pipeline execution.
/// Uses UUID v4 for globally unique, collision-resistant identifiers.
pub fn generate_request_id() -> String {
    Uuid::new_v4().to_string()
}

/// Generates a numeric request ID suitable for prediction request tracking.
/// Uses the lower 64 bits of a UUID v4 to produce a unique numeric identifier.
pub fn generate_numeric_request_id() -> u64 {
    let uuid = Uuid::new_v4();
    let bytes = uuid.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}
