//! Cryptographic verification of record stream files.
//!
//! Every consensus node publishes, next to each record file, a
//! `.rcd_sig` file: SHA-384 of the (uncompressed) record file, signed
//! with the node's RSA-3072 stream key (SHA384withRSA). A record file
//! is network-attested when nodes holding at least one third of the
//! address book agree on the same file.
//!
//! The hash domain is the ENTIRE uncompressed file, version header
//! included, and the signature is over the 48-byte hash itself —
//! established empirically in the TypeScript reference and preserved
//! here bit-for-bit.

use crate::{proto, Error};
use flate2::read::GzDecoder;
use prost::Message;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;
use std::io::Read;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// SHA-384 of a record file, over the uncompressed bytes (as signed).
pub fn record_file_hash(record_file_bytes: &[u8]) -> Result<[u8; 48], Error> {
    let inflated;
    let bytes = if record_file_bytes.len() >= 2 && record_file_bytes[..2] == GZIP_MAGIC {
        let mut out = Vec::new();
        GzDecoder::new(record_file_bytes).read_to_end(&mut out)?;
        inflated = out;
        &inflated[..]
    } else {
        record_file_bytes
    };
    Ok(Sha384::digest(bytes).into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignatureFile {
    /// Signature file format version (currently only 6 is supported)
    pub version: u8,
    /// The node's claimed SHA-384 of the record file
    pub file_hash: Vec<u8>,
    /// RSA-3072 signature over `file_hash`
    pub file_signature: Vec<u8>,
    /// Same pair for the v6 metadata section (not verified here)
    pub metadata_hash: Option<Vec<u8>>,
    pub metadata_signature: Option<Vec<u8>>,
}

/// Parse a v6 `.rcd_sig` file: one version byte, then a protobuf.
pub fn parse_signature_file(bytes: &[u8]) -> Result<ParsedSignatureFile, Error> {
    if bytes.len() < 2 {
        return Err(Error::TooShort);
    }
    let version = bytes[0];
    if version != 6 {
        return Err(Error::UnsupportedSignatureVersion(version));
    }
    let file = proto::SignatureFile::decode(&bytes[1..])?;
    let file_sig = file.file_signature.ok_or(Error::MissingFileSignature)?;
    let file_hash = file_sig
        .hash_object
        .map(|h| h.hash)
        .filter(|h| !h.is_empty())
        .ok_or(Error::MissingFileSignature)?;
    if file_sig.signature.is_empty() {
        return Err(Error::MissingFileSignature);
    }
    Ok(ParsedSignatureFile {
        version,
        file_hash,
        file_signature: file_sig.signature,
        metadata_hash: file
            .metadata_signature
            .as_ref()
            .and_then(|m| m.hash_object.as_ref())
            .map(|h| h.hash.clone()),
        metadata_signature: file.metadata_signature.map(|m| m.signature),
    })
}

/// Verify one node's signature over a file hash. `public_key_hex` is
/// the node's RSA public key as hex-encoded DER (SubjectPublicKeyInfo)
/// — the format both the address book file and the mirror REST API use.
pub fn verify_node_signature(
    file_hash: &[u8],
    signature: &[u8],
    public_key_hex: &str,
) -> Result<bool, Error> {
    let der = hex::decode(public_key_hex.trim_start_matches("0x"))
        .map_err(|e| Error::Key(e.to_string()))?;
    let key = RsaPublicKey::from_public_key_der(&der).map_err(|e| Error::Key(e.to_string()))?;
    let verifying_key = VerifyingKey::<Sha384>::new(key);
    let Ok(sig) = Signature::try_from(signature) else {
        return Ok(false);
    };
    Ok(verifying_key.verify(file_hash, &sig).is_ok())
}

/// node account id ("0.0.3") → RSA public key, hex DER
pub type AddressBook = BTreeMap<String, String>;

/// Parse a serialized NodeAddressBook (system file 0.0.101/0.0.102).
pub fn parse_address_book(bytes: &[u8]) -> Result<AddressBook, Error> {
    let book = proto::NodeAddressBook::decode(bytes)?;
    let mut entries = BTreeMap::new();
    for node in book.node_address {
        let Some(id) = node.node_account_id else {
            continue;
        };
        #[allow(deprecated)]
        let key = node.rsa_pub_key;
        if key.is_empty() {
            continue;
        }
        let num = match id.account {
            Some(proto::account_id::Account::AccountNum(n)) => n,
            _ => continue,
        };
        entries.insert(format!("{}.{}.{}", id.shard_num, id.realm_num, num), key);
    }
    Ok(entries)
}

/// A `.rcd_sig` file downloaded from one node's bucket directory.
pub struct NodeSignature {
    /// Node account id the file came from
    pub node: String,
    /// Raw signature file bytes
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    /// SHA-384 actually computed from the record file
    pub hash: [u8; 48],
    /// Nodes whose signature verifies over the computed hash
    pub valid: Vec<String>,
    /// Nodes whose signature file was provided but does not verify
    pub invalid: Vec<String>,
    /// Nodes not present in the address book (cannot be checked)
    pub unknown: Vec<String>,
    /// Address book size the threshold was computed against
    pub node_count: usize,
    /// True when valid signatures reach at least one third of the
    /// address book — the network's attestation threshold.
    pub attested: bool,
}

/// Verify a record file against signature files from multiple nodes.
/// Signatures are verified over the LOCALLY computed hash, so a node
/// claiming a different hash simply fails — tampering with the record
/// file and tampering with a signature file are the same failure.
pub fn verify_record_file(
    record_file_bytes: &[u8],
    signatures: &[NodeSignature],
    address_book: &AddressBook,
) -> Result<VerifyResult, Error> {
    let hash = record_file_hash(record_file_bytes)?;
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    let mut unknown = Vec::new();
    for sig in signatures {
        let Some(public_key) = address_book.get(&sig.node) else {
            unknown.push(sig.node.clone());
            continue;
        };
        let ok = parse_signature_file(&sig.bytes)
            .and_then(|parsed| verify_node_signature(&hash, &parsed.file_signature, public_key))
            .unwrap_or(false);
        if ok {
            valid.push(sig.node.clone());
        } else {
            invalid.push(sig.node.clone());
        }
    }
    let node_count = address_book.len();
    Ok(VerifyResult {
        hash,
        attested: node_count > 0 && valid.len() * 3 >= node_count,
        valid,
        invalid,
        unknown,
        node_count,
    })
}
