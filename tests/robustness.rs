//! Deterministic robustness sweep: the parsers must return `Ok` or `Err`
//! on mangled input — never panic — because attacker-supplied bytes are
//! this tool's stated use case. Complements the fuzz targets under
//! `fuzz/` (which explore randomly, on a schedule) with a bounded,
//! always-on version that runs in every `cargo test`.

use hiero_streams::{
    detect_format, parse_address_book, parse_block, parse_record_file, parse_signature_file,
};
use std::fs;

fn fixtures(sub: &str, suffix: &str) -> Vec<Vec<u8>> {
    let dir = format!("{}/tests/fixtures/{sub}", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let name = entry.file_name().into_string().unwrap();
        if name.ends_with(suffix) {
            out.push(fs::read(entry.path()).unwrap());
        }
    }
    assert!(!out.is_empty(), "no {suffix} fixtures under {sub}");
    out
}

/// Stepped truncation prefixes and a sweep of single-byte flips. Strides
/// are tuned to keep the whole sweep at a few seconds in CI — the fuzz
/// targets under `fuzz/` own the deep random exploration; this is the
/// always-on smoke layer.
fn mangle_and_feed(bytes: &[u8], feed: &dyn Fn(&[u8])) {
    // truncations: prefixes at a 509-byte stride, plus the empty input
    let mut len = 0;
    while len < bytes.len() {
        feed(&bytes[..len]);
        len += 509;
    }
    // bit flips: every 251st byte, one flip each (headers get dense
    // coverage from the small-offset flips across many fixtures)
    let mut flipped = bytes.to_vec();
    let mut i = 0;
    while i < flipped.len() {
        flipped[i] ^= 0xff;
        feed(&flipped);
        flipped[i] ^= 0xff; // restore
        i += 251;
    }
}

#[test]
fn record_parser_never_panics_on_mangled_input() {
    for bytes in fixtures("mainnet", ".rcd.gz")
        .into_iter()
        .chain(fixtures("v6", ".rcd.gz"))
    {
        mangle_and_feed(&bytes, &|b| {
            let _ = detect_format(b);
            let _ = parse_record_file(b);
        });
    }
}

#[test]
fn block_parser_never_panics_on_mangled_input() {
    for bytes in fixtures("block-preview", ".gz") {
        mangle_and_feed(&bytes, &|b| {
            let _ = detect_format(b);
            let _ = parse_block(b);
        });
    }
}

#[test]
fn signature_and_address_book_parsers_never_panic_on_mangled_input() {
    for bytes in fixtures("v6", ".rcd_sig") {
        mangle_and_feed(&bytes, &|b| {
            let _ = parse_signature_file(b);
        });
    }
    let book = fs::read(format!(
        "{}/tests/fixtures/test-v6-sidecar-4n.bin",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    mangle_and_feed(&book, &|b| {
        let _ = parse_address_book(b);
    });
}
