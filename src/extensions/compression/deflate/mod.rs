//! Implements "permessage-deflate" PMCE defined in [RFC 7692 Section 7]
//!
//! [RFC 7692 Section 7]: https://tools.ietf.org/html/rfc7692#section-7
use std::{io::Write, num::NonZeroU8};

use bytes::Bytes;
use flate2::{
    write::{ZlibDecoder, ZlibEncoder},
    Compress, Decompress,
};
use thiserror::Error;

use crate::protocol::Role;

mod config;
#[cfg_attr(not(feature = "handshake"), allow(unused_imports))]
pub(crate) use config::ParameterError as DeflateParameterError;
pub use config::{
    DeflateConfig, NegotiationError as DeflateNegotiationError, PermessageDeflateConfig,
    PER_MESSAGE_DEFLATE as EXTENSION_NAME,
};

#[derive(Debug)]
/// Manages per message compression using DEFLATE.
pub struct DeflateContext {
    compress: DeflateCompress,
    decompress: DeflateDecompress,
}

/// Errors from `permessage-deflate` extension.
#[derive(Copy, Clone, Debug, Error, PartialEq, Eq)]
pub enum DeflateError {
    /// Compress failed
    #[error("Failed to compress")]
    Compress,
    /// Decompress failed
    #[error("Failed to decompress")]
    Decompress,
}

#[derive(Debug)]
struct DeflateCompress {
    own_context_takeover: bool,
    compressor: ZlibEncoder<Vec<u8>>,
}

#[derive(Debug)]
struct DeflateDecompress {
    decompressor: ZlibDecoder<Vec<u8>>,
    peer_context_takeover: bool,
    peer_window_bits: NonZeroU8,
}

impl DeflateContext {
    pub(crate) fn new(role: Role, config: DeflateConfig) -> Self {
        let DeflateConfig {
            server_no_context_takeover,
            client_no_context_takeover,
            compression,
            ..
        } = config;

        // Per RFC 7692 Section 7:
        //
        //      These parameters enable two methods (no_context_takeover and
        //      max_window_bits) of constraining memory usage that may be
        //      applied independently to either direction of WebSocket traffic.
        //      The extension parameters with the "client_" prefix are used by
        //      the client to configure its compressor and by the server to
        //      configure its decompressor.  The extension parameters with the
        //      "server_" prefix are used by the server to configure its
        //      compressor and by the client to configure its decompressor.  All
        //      four parameters are defined for both a client's extension
        //      negotiation offer and a server's extension negotiation response.
        //
        // Here `role` is for our own end of the connection, as opposed to the
        // peer end.
        let (own_no_context_takeover, peer_no_context_takeover) = match role {
            Role::Client => (client_no_context_takeover, server_no_context_takeover),
            Role::Server => (server_no_context_takeover, client_no_context_takeover),
        };

        // Both ends of the connection act as both compressor and decompressor.
        // We compress with the window size for our role and decompress with the
        // size for the opposite role.
        let (compressor_window_bits, decompressor_window_bits) = match role {
            Role::Client => (config.client_max_window_bits(), config.server_max_window_bits()),
            Role::Server => (config.server_max_window_bits(), config.client_max_window_bits()),
        };

        DeflateContext {
            compress: DeflateCompress {
                own_context_takeover: !own_no_context_takeover,
                compressor: ZlibEncoder::new_with_compress(
                    Vec::new(),
                    Compress::new_with_window_bits(
                        compression,
                        false,
                        compressor_window_bits.get(),
                    ),
                ),
            },
            decompress: DeflateDecompress {
                peer_context_takeover: !peer_no_context_takeover,
                decompressor: ZlibDecoder::new_with_decompress(
                    Vec::new(),
                    Decompress::new_with_window_bits(false, decompressor_window_bits.get()),
                ),
                peer_window_bits: decompressor_window_bits,
            },
        }
    }

    /// Compress the payload of an outgoing message.
    pub(crate) fn compress(&mut self, data: &[u8]) -> Result<Bytes, DeflateError> {
        self.compress.compress(data).map_err(|e| {
            log::debug!("compression failed: {e}");
            DeflateError::Compress
        })
    }

    /// Decompress the payload in a received frame.
    ///
    /// The `is_final` argument should only be set when calling with the contents of the last frame in a message.
    pub(crate) fn decompress(
        &mut self,
        data: &[u8],
        is_final: bool,
    ) -> Result<Bytes, DeflateError> {
        self.decompress.decompress(data, is_final).map_err(|e| {
            log::debug!("decompression failed: {e}");
            DeflateError::Decompress
        })
    }
}

const ELIDED_TRAILER_BLOCK_CONTENTS: &[u8] = &[0x00, 0x00, 0xff, 0xff];

impl DeflateCompress {
    /// Compress the contents of an entire message.
    ///
    /// This is asymmetric with [`DeflateDecompress::decompress`] in that it
    /// operates on the contents of an entire message, not the comprising frames.
    fn compress(&mut self, data: &[u8]) -> Result<Bytes, std::io::Error> {
        // Make sure the backing buffer doesn't start out empty. This isn't
        // necessary for correctness.
        self.compressor.get_mut().reserve(data.len());

        // Per RFC 7692 Section 7.2.1:
        //
        //     An endpoint uses the following algorithm to compress a message.
        //
        //     1.  Compress all the octets of the payload of the message using
        //         DEFLATE.
        //

        self.compressor.write_all(data)?;
        self.compressor.flush()?;

        //     2.  If the resulting data does not end with an empty DEFLATE
        //         block with no compression (the "BTYPE" bits are set to 00),
        //         append an empty DEFLATE block with no compression to the tail
        //         end.
        if !self.compressor.get_ref().ends_with(ELIDED_TRAILER_BLOCK_CONTENTS) {
            self.compressor.flush()?;
        }

        //     3.  Remove 4 octets (that are 0x00 0x00 0xff 0xff) from the tail
        //         end.  After this step, the last octet of the compressed data
        //         contains (possibly part of) the DEFLATE header bits with the
        //         "BTYPE" bits set to 00.

        let mut output = std::mem::take(self.compressor.get_mut());
        debug_assert!(output.ends_with(ELIDED_TRAILER_BLOCK_CONTENTS), "output is {output:02x?}");
        output.truncate(output.len() - ELIDED_TRAILER_BLOCK_CONTENTS.len());

        if !self.own_context_takeover {
            // Reset if the next frame isn't supposed to be starting with the
            // same compression window.
            self.compressor.reset(Vec::new())?;
        }

        Ok(Bytes::from(output))
    }
}

impl DeflateDecompress {
    /// Decompress the contents of a single frame.
    ///
    /// The `is_final` argument must be `true` if and only if the frame is the
    /// last one in a message.
    fn decompress(&mut self, data: &[u8], is_final: bool) -> Result<Bytes, std::io::Error> {
        // From RFC 7692 Section 7.2.2:
        //
        //   An endpoint uses the following algorithm to decompress a message.
        //
        //   1.  Append 4 octets of 0x00 0x00 0xff 0xff to the tail end of the
        //       payload of the message.
        //
        //   2.  Decompress the resulting data using DEFLATE.

        self.decompressor.get_mut().reserve(
            // Optimistically assume a 50% compression ratio of the input.
            2 * data.len(),
        );

        // Decompress the input received over the wire. That might not be all of
        // the logical input to DEFLATE so don't try to sync.
        self.decompressor.write_all(data)?;

        let mut output = None;
        if is_final {
            // Decompress the final block that is part of the logical input to
            // DEFLATE but is elided from the message payloads.
            self.decompressor.write_all(ELIDED_TRAILER_BLOCK_CONTENTS)?;
            self.decompressor.flush()?;

            if !self.peer_context_takeover {
                // This wholesale replacement shouldn't be needed but
                // `ZlibDecoder::finish` assumes that the new input will have a
                // zlib header, which isn't the case here, and doesn't have a
                // way to override it.
                let decompressor = std::mem::replace(
                    &mut self.decompressor,
                    ZlibDecoder::new_with_decompress(
                        Vec::new(),
                        Decompress::new_with_window_bits(false, self.peer_window_bits.get()),
                    ),
                );
                output = Some(decompressor.finish()?);
            }
        }
        let output = output.unwrap_or_else(|| std::mem::take(self.decompressor.get_mut()));

        Ok(Bytes::from(output))
    }
}

impl From<DeflateContext> for super::PerMessageCompressionContext {
    fn from(value: DeflateContext) -> Self {
        Self::Deflate(value)
    }
}

#[cfg(test)]
mod test {
    use rand::{RngCore, SeedableRng as _};

    use super::*;

    #[test]
    fn interop() {
        let mut data = vec![0; 2048];
        rand::rngs::SmallRng::seed_from_u64(1023).fill_bytes(&mut data);

        let configs = [
            DeflateConfig::default(),
            DeflateConfig::default().set_no_context_takeover(Role::Client, true),
            DeflateConfig::default()
                .set_no_context_takeover(Role::Client, true)
                .set_max_window_bits(Role::Client, 10)
                .unwrap(),
            DeflateConfig::default().set_max_window_bits(Role::Client, 10).unwrap(),
        ];

        let frame_sizes = [16, 64, data.len()];

        for config in configs {
            for frame_size in frame_sizes {
                let mut client = DeflateContext::new(Role::Client, config);
                let mut server = DeflateContext::new(Role::Server, config);

                let mut send_and_receive = |data| {
                    let compressed = client.compress(data).unwrap();

                    let mut decompressed = Vec::<u8>::new();

                    let mut it = compressed.chunks(frame_size).peekable();
                    while let Some(frame) = it.next() {
                        decompressed.extend_from_slice(
                            &server.decompress(frame, it.peek().is_none()).unwrap(),
                        );
                    }
                    decompressed
                };

                let decompressed = send_and_receive(&data);
                assert_eq!(data, decompressed);

                // Make sure we haven't broken compression or decompression for
                // the *next* message.
                let decompressed = send_and_receive(b"second message");
                assert_eq!(decompressed, b"second message");
            }
        }
    }

    #[test]
    fn large_message_compression() {
        let mut data = vec![0; 1 << 19];
        rand::rngs::SmallRng::seed_from_u64(1023).fill_bytes(&mut data);

        let mut context = DeflateContext::new(Role::Client, DeflateConfig::default());

        let compressed = context.compress(&data).unwrap();

        assert_eq!(&context.decompress(&compressed, true).unwrap(), &data);
    }

    mod rfc_7692_section_7_2_3_examples {
        use super::*;

        #[test]
        fn one_block() {
            // From RFC 7692 Section 7.2.3.1:
            //
            //   Suppose that an endpoint sends a text message "Hello".  If the
            //   endpoint uses one compressed DEFLATE block (compressed with fixed
            //   Huffman code and the "BFINAL" bit not set) to compress the message,
            //   the endpoint obtains the compressed data to use for the message
            //   payload as follows.
            //
            //   The endpoint compresses "Hello" into one compressed DEFLATE block and
            //   flushes the resulting data into a byte array using an empty DEFLATE
            //   block with no compression:
            //
            //       0xf2 0x48 0xcd 0xc9 0xc9 0x07 0x00 0x00 0x00 0xff 0xff
            //
            //   By stripping 0x00 0x00 0xff 0xff from the tail end, the endpoint gets
            //   the data to use for the message payload:
            //
            const EXPECTED_COMPRESSED_PAYLOAD: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];

            let mut context = DeflateContext::new(Role::Server, DeflateConfig::default());
            let compressed = context.compress(b"Hello").unwrap();
            assert_eq!(&compressed[..], EXPECTED_COMPRESSED_PAYLOAD);
            //
            //   ...
            //
            //   Suppose that the endpoint sends the compressed message with
            //   fragmentation.  The endpoint splits the compressed data into
            //   fragments and builds frames for each fragment.  For example, if the
            //   fragments are 3 and 4 octets,
            //
            const FRAGMENTED_FRAMES: &[&[u8]] = &[
                //  the first frame is:
                &[0x41, 0x03, 0xf2, 0x48, 0xcd],
                //   and the second frame is:
                &[0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00],
            ];
            //
            //   Note that the RSV1 bit is set only on the first frame.

            let frame_payloads =
                FRAGMENTED_FRAMES.iter().map(|frame| &frame[2..]).collect::<Vec<_>>();

            let decompressed = frame_payloads
                .iter()
                .enumerate()
                .map(|(index, payload)| {
                    context.decompress(payload, index == frame_payloads.len() - 1)
                })
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .concat();

            assert_eq!(decompressed, b"Hello");
        }

        #[test]
        fn sharing_sliding_window() {
            const ROLE: Role = Role::Client;

            // From RFC 7692 Section 7.2.3.2:
            //
            //   Suppose that a client has sent a message "Hello" as a compressed
            //   message and will send the same message "Hello" again as a compressed
            //   message.
            //
            const FIRST_PAYLOAD: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
            //
            //   The above is the payload of the first message that the client has
            //   sent.  If the "agreed parameters" contain the
            //   "client_no_context_takeover" extension parameter, the client
            //   compresses the payload of the next message into the same bytes (if
            //   the client uses the same "BTYPE" value and "BFINAL" value).  So, the
            //   payload of the second message will be:
            //
            const SECOND_PAYLOAD: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];

            let mut context = DeflateContext::new(
                ROLE,
                DeflateConfig::default().set_no_context_takeover(ROLE, true),
            );
            assert_eq!(&context.compress(b"Hello").unwrap()[..], FIRST_PAYLOAD);
            assert_eq!(&context.compress(b"Hello").unwrap()[..], SECOND_PAYLOAD);

            //
            //   If the "agreed parameters" did not contain the
            //   "client_no_context_takeover" extension parameter, the client can
            //   compress the payload of the next message into fewer bytes by
            //   referencing the history in the LZ77 sliding window.  So, the payload
            //   of the second message will be:
            //
            const NEW_SECOND_PAYLOAD: &[u8] = &[0xf2, 0x00, 0x11, 0x00, 0x00];

            let mut context = DeflateContext::new(ROLE, DeflateConfig::default());
            assert_eq!(&context.compress(b"Hello").unwrap()[..], FIRST_PAYLOAD);
            assert_eq!(&context.compress(b"Hello").unwrap()[..], NEW_SECOND_PAYLOAD);
        }

        #[test]
        fn two_deflate_blocks() {
            // From RFC 7692 Section 7.2.3.5:
            //
            //   Two or more DEFLATE blocks may be used in one message.

            const TWO_BLOCKS: &[u8] =
                &[0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00];

            let mut context = DeflateContext::new(Role::Client, DeflateConfig::new());

            assert_eq!(&context.decompress(TWO_BLOCKS, true).unwrap()[..], b"Hello");
        }
    }
}
