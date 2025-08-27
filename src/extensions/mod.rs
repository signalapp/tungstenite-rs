//! WebSocket extensions.
// Only `permessage-deflate` is supported at the moment.

pub mod compression;

#[cfg(feature = "headers")]
pub(crate) mod headers;
