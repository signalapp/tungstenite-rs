//! [Per-Message Compression Extensions][rfc7692]
//!
//! [rfc7692]: https://tools.ietf.org/html/rfc7692

use bytes::Bytes;
use thiserror::Error;

#[cfg(feature = "deflate")]
pub mod deflate;

/// Active context for performing per-message compression.
#[derive(Debug)]
#[cfg_attr(not(feature = "deflate"), allow(missing_copy_implementations))] // This is only trivially copyable if compression is disabled.
pub enum PerMessageCompressionContext {
    /// Context for compressing/decompressing with `permessage-deflate`.
    #[cfg(feature = "deflate")]
    Deflate(deflate::DeflateContext),
}

/// Error encountered while compressing or decompressing.
#[derive(Copy, Clone, Debug, Error, PartialEq, Eq)]
pub enum CompressionError {
    /// Error encountered while deflating or inflating
    #[error("Deflate error: {0}")]
    #[cfg(feature = "deflate")]
    Deflate(deflate::DeflateError),
}

impl PerMessageCompressionContext {
    #[inline]
    pub(crate) fn compressor<'s>(
        &'s mut self,
    ) -> impl FnMut(&Bytes) -> Result<Bytes, CompressionError> + 's {
        move |payload: &Bytes| match self {
            #[cfg(feature = "deflate")]
            Self::Deflate(deflate_config) => {
                deflate_config.compress(payload).map_err(CompressionError::Deflate)
            }
            #[cfg(not(feature = "deflate"))]
            _ => {
                let _ = payload;
                unreachable!("*PerMessageCompressionContext is uninhabited")
            }
        }
    }

    #[inline]
    pub(crate) fn decompressor<'s>(
        &'s mut self,
    ) -> impl FnMut(&Bytes, bool) -> Result<Bytes, CompressionError> + 's {
        move |payload, is_final| match self {
            #[cfg(feature = "deflate")]
            Self::Deflate(deflate_config) => {
                deflate_config.decompress(payload, is_final).map_err(CompressionError::Deflate)
            }
            #[cfg(not(feature = "deflate"))]
            _ => {
                let _ = (payload, is_final);
                unreachable!("*PerMessageCompressionContext is uninhabited")
            }
        }
    }
}
