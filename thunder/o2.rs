//! O2 (Observability) module for Thunder service.
//!
//! Provides observability hooks and trace context propagation utilities.
//! This module is declared in `lib.rs` for use by internal observability
//! infrastructure.

/// Placeholder for O2 observability context — the actual implementation
/// is backed by the internal `xai_o2` crate at deployment time.
pub struct O2Context;

impl O2Context {
    /// Create a default observability context.
    pub fn new() -> Self {
        Self
    }
}

impl Default for O2Context {
    fn default() -> Self {
        Self::new()
    }
}
