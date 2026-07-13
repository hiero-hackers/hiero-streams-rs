//! Shallow protobuf wire scan of a `Block` message.
//!
//! Proof extraction can't reuse the typed prost decode in
//! [`crate::block`]: the block merkle tree hashes the EXACT serialized
//! bytes of each `BlockItem` as they appear in the file, and a re-encode
//! of a decoded item is not guaranteed byte-identical. This walks the
//! wire format just far enough to slice out each item's original bytes
//! and identify which oneof field it carries — without decoding the
//! payload. All reads are bounds-checked (untrusted input).

use crate::Error;

// BlockItem oneof field numbers (proto-hapi/block/stream/block_item.proto).
pub(super) const F_BLOCK_HEADER: u64 = 1;
pub(super) const F_EVENT_HEADER: u64 = 2;
pub(super) const F_ROUND_HEADER: u64 = 3;
pub(super) const F_SIGNED_TRANSACTION: u64 = 4;
pub(super) const F_TRANSACTION_RESULT: u64 = 5;
pub(super) const F_TRANSACTION_OUTPUT: u64 = 6;
pub(super) const F_STATE_CHANGES: u64 = 7;
pub(super) const F_FILTERED_SINGLE_ITEM: u64 = 8;
pub(super) const F_BLOCK_PROOF: u64 = 9;
pub(super) const F_RECORD_FILE: u64 = 10;
pub(super) const F_TRACE_DATA: u64 = 11;
pub(super) const F_BLOCK_FOOTER: u64 = 12;
pub(super) const F_REDACTED_ITEM: u64 = 19;

/// One scanned `BlockItem`: which oneof field it populates, and its exact
/// wire bytes (the merkle leaf).
pub(super) struct ScannedItem<'a> {
    pub(super) field_number: u64,
    /// The whole `BlockItem` message as serialized in the file.
    pub(super) item_bytes: &'a [u8],
}

fn read_varint(bytes: &[u8], mut offset: usize) -> Result<(u64, usize), Error> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        let byte = *bytes
            .get(offset)
            .ok_or_else(|| Error::Proof("truncated varint".into()))?;
        value |= u64::from(byte & 0x7f) << shift;
        offset += 1;
        if byte & 0x80 == 0 {
            return Ok((value, offset));
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::Proof("varint exceeds 64 bits".into()));
        }
    }
}

fn read_length_delimited(bytes: &[u8], offset: usize) -> Result<(&[u8], usize), Error> {
    let (length, start) = read_varint(bytes, offset)?;
    let end = start
        .checked_add(usize::try_from(length).map_err(|_| Error::Proof("length overflow".into()))?)
        .ok_or_else(|| Error::Proof("length overflow".into()))?;
    if end > bytes.len() {
        return Err(Error::Proof(
            "length-delimited field exceeds available bytes".into(),
        ));
    }
    Ok((&bytes[start..end], end))
}

/// Scan the top-level `Block` message: every field-1 length-delimited
/// value is one `BlockItem`, kept as its exact wire bytes.
pub(super) fn scan_block_items(block_bytes: &[u8]) -> Result<Vec<ScannedItem<'_>>, Error> {
    let mut items = Vec::new();
    let mut offset = 0;
    while offset < block_bytes.len() {
        let (tag, after_tag) = read_varint(block_bytes, offset)?;
        let field_number = tag >> 3;
        if tag & 0x07 != 2 {
            return Err(Error::Proof(format!(
                "unsupported Block wire type {} for field {field_number}",
                tag & 0x07
            )));
        }
        let (item_bytes, next) = read_length_delimited(block_bytes, after_tag)?;
        if field_number == 1 {
            items.push(ScannedItem {
                field_number: scan_item_kind(item_bytes)?,
                item_bytes,
            });
        }
        offset = next;
    }
    Ok(items)
}

/// Determine which oneof field a `BlockItem` populates without decoding
/// its payload.
fn scan_item_kind(item_bytes: &[u8]) -> Result<u64, Error> {
    let mut offset = 0;
    let mut found: Option<u64> = None;
    while offset < item_bytes.len() {
        let (tag, after_tag) = read_varint(item_bytes, offset)?;
        let field_number = tag >> 3;
        if tag & 0x07 != 2 {
            return Err(Error::Proof(format!(
                "unsupported BlockItem wire type {} for field {field_number}",
                tag & 0x07
            )));
        }
        let (_, next) = read_length_delimited(item_bytes, after_tag)?;
        if found.replace(field_number).is_some() {
            return Err(Error::Proof(
                "BlockItem has multiple populated oneof fields".into(),
            ));
        }
        offset = next;
    }
    found.ok_or_else(|| Error::Proof("empty BlockItem".into()))
}
