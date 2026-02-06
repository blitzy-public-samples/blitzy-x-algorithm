//! General event schema definitions (Thrift-generated equivalents).

use thrift::protocol::{TBinaryInputProtocol, TSerializable};

/// Generic event wrapper used for Kafka message deserialization.
#[derive(Debug, Clone, Default)]
pub struct Event {
    pub event_type: Option<String>,
    pub payload: Option<Vec<u8>>,
}

impl TSerializable for Event {
    fn read_from_in_protocol<R: std::io::Read>(
        _protocol: &mut TBinaryInputProtocol<R>,
    ) -> std::io::Result<Self> {
        // Stub: return an empty event — real implementation is Thrift-generated.
        Ok(Event::default())
    }
}
