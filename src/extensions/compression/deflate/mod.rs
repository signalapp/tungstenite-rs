//! Implements "permessage-deflate" PMCE defined in [RFC 7692 Section 7]
//!
//! [RFC 7692 Section 7]: https://tools.ietf.org/html/rfc7692#section-7
#![allow(dead_code)]

mod config;
pub use config::{
    DeflateConfig, NegotiationError as DeflateNegotiationError, PermessageDeflateConfig,
};
