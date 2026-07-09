//! Parse and cryptographically verify Hedera **record stream files** —
//! the signed consensus output every mainnet node publishes.
//!
//! Correctness is established differentially: the test suite asserts
//! field-for-field equality against golden output from the reference
//! TypeScript implementation (hiero-recordstreams), which is itself
//! validated byte-exact against mainnet via the mirror node REST API.
//!
//! Currently v6 record files (mainnet mid-2022 onward). Block streams
//! (HIP-1056) are the planned second format behind the same API.

pub mod parse;
pub mod verify;

/// Generated protobuf types, compiled from the vendored
/// `@hashgraph/proto@2.25.0` definitions (see `build.rs`). The
/// wrapper spans every protobuf package in the closure; the Hedera
/// messages live in `generated::proto`.
#[allow(clippy::all, dead_code)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hiero_protos.rs"));
}
pub use generated::proto;

pub use parse::{parse_record_file, ParsedRecordFile, ParsedTransaction, TransferLeg};
pub use verify::{
    parse_address_book, parse_signature_file, record_file_hash, verify_node_signature,
    verify_record_file, AddressBook, NodeSignature, ParsedSignatureFile, VerifyResult,
};

/// Errors surfaced by parsing and verification.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("record file too short to contain a version header")]
    TooShort,
    #[error("unsupported record file version {0} — only v6 is implemented")]
    UnsupportedVersion(i32),
    #[error("unsupported signature file version {0} — only v6 is implemented")]
    UnsupportedSignatureVersion(u8),
    #[error("signature file has no file signature")]
    MissingFileSignature,
    #[error("gzip: {0}")]
    Gzip(#[from] std::io::Error),
    #[error("protobuf: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("public key: {0}")]
    Key(String),
}
