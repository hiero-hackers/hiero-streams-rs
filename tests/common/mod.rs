//! Shared test helpers (a `common/` module dir, so cargo does not
//! treat it as its own test binary).
use std::fs;
use std::path::Path;

/// Read a bundled fixture by path relative to `tests/fixtures/`.
pub fn fixture(name: &str) -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/{name}"))).unwrap()
}
