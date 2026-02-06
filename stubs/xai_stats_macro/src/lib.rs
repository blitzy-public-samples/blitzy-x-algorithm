//! Stub proc-macro crate for xai_stats_macro — provides instrumentation
//! attributes for metrics collection. In this stub, the macros are pass-through
//! (no-op), preserving the function bodies unchanged.

use proc_macro::TokenStream;

/// Attribute macro applied to async trait methods to collect execution metrics.
/// In this stub, it is a no-op pass-through that returns the function unchanged.
#[proc_macro_attribute]
pub fn receive_stats(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// Attribute macro applied to the main function to initialize metrics runtime.
/// In this stub, it is a no-op pass-through that returns the function unchanged.
/// The actual `#[tokio::main]` attribute is applied separately by the user code.
#[proc_macro_attribute]
pub fn main(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
