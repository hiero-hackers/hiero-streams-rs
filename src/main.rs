//! hiero-streams CLI — the library as a distributable trust tool.
//!
//!   hiero-streams parse <file.rcd.gz>
//!       Print the parsed transactions as JSON.
//!
//!   hiero-streams verify <file.rcd.gz> <file.rcd_sig>
//!         (--address-book <book.bin> --node <0.0.N> | --public-key <hexDER>)
//!       Verify a node's signature over the record file. Exits 0 only
//!       when the signature is valid.
//!
//!   hiero-streams verify <file.blk[.gz]> [--bootstrap <genesis.blk[.gz]>]
//!       (requires --features block-proofs) Verify the block's in-band
//!       proof: recomputed merkle root, hinTS threshold signature, and
//!       the Schnorr/WRAPS suffix. Blocks arrive pre-signed, so there
//!       is no signature file and nothing to fetch; the ledger-ID
//!       publication lives in the genesis block only, so non-genesis
//!       blocks need --bootstrap.
//!
//!   hiero-streams block-activity <file.blk[.gz]>...
//!       Per-block node liveness: which consensus nodes authored
//!       gossip events in each block, and how many.
//!
//! The implementation lives in [`cli`]; this is just the entry point.

mod cli;

fn main() -> std::process::ExitCode {
    cli::run(std::env::args().skip(1).collect())
}
