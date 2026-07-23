//! Parse and cryptographically verify Hedera's **consensus streams** —
//! the signed output every mainnet node publishes — in both eras:
//! v6 record files (mainnet mid-2022 onward) and HIP-1056 block
//! streams, behind one era-detecting API.
//!
//! Correctness is anchored to the network itself: the consensus nodes'
//! signed metadata hashes reproduce from this parser's own extracted
//! fields (the network attests the parse), transaction-level output is
//! differentially tested against the mirror node's independent
//! decoding of the same mainnet files, and block-era proof
//! verification (the `verify_*` functions behind the `block-proofs`
//! feature) is differentially tested
//! check-for-check against an independent implementation. Committed
//! snapshots pin the canonical output shape against silent change.

// This crate parses attacker-controlled bytes, so its memory safety is
// load-bearing. `forbid` (not `deny`, which an inner `#[allow]` could
// override) makes it a compile error for any code here — including the
// generated protobuf modules — to use `unsafe`. The parse/verify core
// is provably free of memory-unsafety; only third-party dependencies
// (to which this does not apply) carry `unsafe`.
#![forbid(unsafe_code)]

// The module tree is private on purpose: the crate-root re-exports in
// the "Public API" section below are the crate's ONLY public paths, so
// the tree can be reorganized as the project grows without a breaking
// release. Public modules can always be added later; they can never be
// removed.
mod block;
mod json;
mod record;
mod transaction;

use flate2::read::GzDecoder;
use std::io::Read;

pub(crate) const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Decompressed-size ceiling. Real v6 files inflate to single-digit
/// megabytes; the ceiling guards a tool that parses attacker-supplied
/// bytes (an auditor's exact use case) against decompression bombs.
pub(crate) const MAX_INFLATED: u64 = 1 << 30; // 1 GiB

/// Inflate `.rcd.gz` bytes; pass `.rcd` bytes through unchanged. The
/// one place gzip is handled — parsing and both hash domains share it.
pub(crate) fn inflate(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() >= 2 && bytes[..2] == GZIP_MAGIC {
        let mut out = Vec::new();
        GzDecoder::new(bytes)
            .take(MAX_INFLATED + 1)
            .read_to_end(&mut out)?;
        if out.len() as u64 > MAX_INFLATED {
            return Err(Error::TooLarge);
        }
        Ok(out)
    } else {
        Ok(bytes.to_vec())
    }
}

/// The lowerCamelCase oneof case name from a value's `Debug` rendering
/// (`CryptoTransfer(..)` → `cryptoTransfer`), WITHOUT rendering its
/// payload. `write!` streams the `Debug` output through a sink that
/// captures the leading identifier and returns `Err` at the first
/// delimiter, which aborts the formatter before it walks the (possibly
/// large) body — the transaction-type derivation was ~38% of parse
/// time when it formatted the whole body. Both eras' `oneof_case_name`
/// delegate here, so their naming is identical by construction (the
/// parity test in the test module still guards it).
pub(crate) fn debug_variant_camel(data: &impl std::fmt::Debug) -> String {
    use std::fmt::Write;
    struct Prefix(String);
    impl Write for Prefix {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            for ch in s.chars() {
                if matches!(ch, '(' | ' ' | '{') {
                    return Err(std::fmt::Error); // variant name captured — stop
                }
                self.0.push(ch);
            }
            Ok(())
        }
    }
    let mut prefix = Prefix(String::new());
    let _ = write!(prefix, "{data:?}"); // Err is the expected early-abort
    let mut chars = prefix.0.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => "unknown".to_string(),
    }
}

/// Stream file format, from the leading version header. The era router
/// that [`detect_format`] returns; the two eras' parsers handle the
/// rest.
///
/// `#[non_exhaustive]`: more eras/versions will appear (block-stream
/// GA, a hypothetical v7). Match with a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    RecordFileV6,
    /// HIP-1056 block stream: a raw protobuf `Block` with no version
    /// header (first byte is a protobuf field-1 tag).
    BlockStream,
    Unknown(i32),
}

/// Identify a stream file's format without fully parsing it — only the
/// first four (decompressed) bytes are read, so detection stays O(1)
/// regardless of file size. This is the crate's entry point: route the
/// result to [`parse_record_file`] or [`parse_block`].
pub fn detect_format(bytes: &[u8]) -> Result<Format, Error> {
    let mut buf = [0u8; 4];
    if bytes.len() >= 2 && bytes[..2] == GZIP_MAGIC {
        GzDecoder::new(bytes)
            .read_exact(&mut buf)
            .map_err(|_| Error::TooShort)?;
    } else {
        if bytes.len() < 4 {
            return Err(Error::TooShort);
        }
        buf.copy_from_slice(&bytes[..4]);
    }
    let version = i32::from_be_bytes(buf);
    Ok(match version {
        6 => Format::RecordFileV6,
        // Block streams carry no version header: the first byte is the
        // protobuf tag for `Block.items` (field 1, wire type 2 = 0x0a),
        // which as a big-endian i32 is huge — unambiguous vs the small
        // integers record-file versions use.
        _ if buf[0] == 0x0a => Format::BlockStream,
        v => Format::Unknown(v),
    })
}

/// Generated protobuf types, compiled from the vendored
/// `@hashgraph/proto@2.25.0` definitions (see `build.rs`). The
/// wrapper spans every protobuf package in the closure; the Hedera
/// messages live in `generated::proto`.
#[allow(clippy::all, dead_code, rustdoc::all)]
pub(crate) mod generated {
    include!(concat!(env!("OUT_DIR"), "/rcd/hiero_protos.rs"));
}
/// Raw generated record-era protobuf types. **Exempt from the crate's
/// semver contract** and hidden from the docs: their shape tracks the
/// vendored proto version and prost's codegen, so re-vendoring protos
/// or bumping prost may change them without a major release. Exposed
/// only as a power-user convenience — the crate's own API takes `&[u8]`
/// and returns the typed structs above.
#[doc(hidden)]
pub use generated::proto;

/// Generated block-stream protobuf types, compiled from the vendored
/// hiero-consensus-node HAPI tree (see `proto-hapi/VENDOR_COMMIT`).
#[allow(clippy::all, dead_code, rustdoc::all)]
pub(crate) mod generated_hapi {
    include!(concat!(env!("OUT_DIR"), "/hapi/hapi_protos.rs"));
}
/// Raw generated block-era protobuf types — semver-exempt, same caveat
/// as [`proto`].
#[doc(hidden)]
pub use generated_hapi::com::hedera::hapi::block::stream as block_proto;

// ─── Public API ──────────────────────────────────────────────────────────────
//
// These crate-root re-exports are the crate's stable API — and its only
// public paths: the module tree (`record`, `block`, `block::proof`, …)
// is private, so it can keep reorganizing without breaking releases.
// `Format`/`detect_format` (the era router) and `Error` are defined
// directly in this file.

// Shared: the transaction vocabulary both eras produce, and its JSON.
pub use json::{block_to_json_value, record_file_to_json_value};
pub use transaction::{
    day_of, AccountId, NftTransfer, ParsedTransaction, TokenId, TokenTransferLeg, TransferLeg,
};

// Record-stream era (v6): parsing + trust.
pub use record::verify::{
    parse_address_book, parse_signature_file, record_file_hash, record_file_metadata_hash,
    verify_metadata_signature, verify_node_signature, verify_record_file,
    verify_running_hash_chain, AddressBook, ChainBreak, NodeSignature, ParsedSignatureFile,
    VerifyResult,
};
pub use record::{parse_record_file, ParsedRecordFile};

// Block-stream era (HIP-1056): reading (always on).
pub use block::material::{
    block_chain_info, extract_proof_material, resolve_bootstrap, BlockChainInfo,
    BlockProofMaterial, Bootstrap, NodeContribution, ProofLayout, ProofPath,
};
pub use block::material::{block_inclusion_witness, recompute_block_root, BlockInclusionWitness};
pub use block::{block_activity, parse_block, BlockActivity, ParsedBlock};
pub use block::{fold_witness, merkle_root, witness_for, MerkleWitness, Side};

// Block-stream era: proof verification (behind `block-proofs`).
#[cfg(feature = "block-proofs")]
pub use block::proof::{
    verify_block_proof, verify_hints, verify_inclusion, verify_schnorr, verify_wraps,
    BlockProofVerification, HintsChecks, SchnorrVerification, WrapsChecks,
};
#[cfg(feature = "block-proofs")]
pub use json::block_proof_to_json_value;

/// Errors surfaced by parsing and verification.
///
/// `#[non_exhaustive]`: this is a pre-GA format's error vocabulary and
/// will gain variants (block-stream GA, new proof schemes). Match with
/// a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("stream file too short to contain a header")]
    TooShort,
    #[error("decompressed data exceeds the 1 GiB safety ceiling")]
    TooLarge,
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
    #[error("block proof: {0}")]
    Proof(String),
}

#[cfg(test)]
mod tests {
    /// `oneof_case_name` derives transaction-type names from prost's Debug
    /// output — these are the tripwires that fire if a prost upgrade ever
    /// changes that format, and the parity check that keeps the two eras'
    /// copies (parse.rs / block.rs) from drifting apart.
    #[test]
    fn oneof_case_name_known_variants() {
        use crate::proto::transaction_body::Data;
        let cases = [
            (
                crate::record::oneof_case_name(&Data::CryptoTransfer(Default::default())),
                "cryptoTransfer",
            ),
            (
                crate::record::oneof_case_name(&Data::ContractCall(Default::default())),
                "contractCall",
            ),
            (
                crate::record::oneof_case_name(&Data::ConsensusSubmitMessage(Default::default())),
                "consensusSubmitMessage",
            ),
        ];
        for (actual, expected) in cases {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn oneof_case_name_eras_agree() {
        use crate::generated_hapi::proto::transaction_body::Data as BlockData;
        use crate::proto::transaction_body::Data as RcdData;
        // Equivalent variants from the two proto namespaces must map to the
        // same case name — this is the keep-in-sync contract between the
        // record-era and block-era parsers.
        assert_eq!(
            crate::record::oneof_case_name(&RcdData::CryptoTransfer(Default::default())),
            crate::block::oneof_case_name(&BlockData::CryptoTransfer(Default::default())),
        );
        assert_eq!(
            crate::record::oneof_case_name(&RcdData::TokenMint(Default::default())),
            crate::block::oneof_case_name(&BlockData::TokenMint(Default::default())),
        );
    }

    #[test]
    fn day_of_epoch_boundaries() {
        assert_eq!(crate::transaction::day_of("0.000000000"), "1970-01-01");
        assert_eq!(crate::transaction::day_of("86399.999999999"), "1970-01-01");
        assert_eq!(crate::transaction::day_of("86400.000000000"), "1970-01-02");
        // leap-year day, mid-era mainnet timestamp
        assert_eq!(
            crate::transaction::day_of("1709164800.000000000"),
            "2024-02-29"
        );
    }
}
