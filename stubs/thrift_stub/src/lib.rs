//! Stub crate for thrift — provides Thrift binary protocol deserialization.

pub mod protocol {
    use std::io::Read;

    /// Thrift binary input protocol (stub).
    pub struct TBinaryInputProtocol<'a, R: Read> {
        _reader: &'a mut R,
    }

    impl<'a, R: Read> TBinaryInputProtocol<'a, R> {
        pub fn new(reader: &'a mut R, _strict: bool) -> Self {
            Self { _reader: reader }
        }
    }

    /// Trait for types that can be deserialized from a Thrift protocol.
    pub trait TSerializable: Sized {
        fn read_from_in_protocol<R: Read>(
            _protocol: &mut TBinaryInputProtocol<R>,
        ) -> std::io::Result<Self>;
    }
}
