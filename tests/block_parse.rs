//! Block-stream (HIP-1056 preview) parsing against a real mainnet
//! block. Expectations were validated live against the mirror node
//! REST API: all 6 user transactions matched field-for-field
//! (timestamp + type + payer + fee + result) in the block's
//! consensus-timestamp window.

mod common;
use common::fixture;
use hiero_streams::{detect_format, parse_block, Format};

const BLK: &str = "block-preview/000000000000000000000000000104356004.blk.gz";

#[test]
fn detects_block_stream_format() {
    assert_eq!(detect_format(&fixture(BLK)).unwrap(), Format::BlockStream);
    // and record files still detect as v6
    assert_eq!(
        detect_format(&fixture("v6/2022-07-13T08_46_11.304284003Z.rcd.gz")).unwrap(),
        Format::RecordFileV6
    );
}

#[test]
fn parses_a_live_preview_block() {
    let block = parse_block(&fixture(BLK)).unwrap();
    assert_eq!(block.block_number, 104_356_004);
    assert_eq!(block.hapi_version, "0.74.3");
    assert_eq!(block.rounds, [253_610_156, 253_610_157, 253_610_158]);
    assert_eq!(block.transactions.len(), 6);

    // First transaction, mirror-verified (an Ethereum tx that failed
    // with WRONG_NONCE — failures carry fees and results too).
    let t = &block.transactions[0];
    assert_eq!(t.consensus_timestamp, "1783621064.717357000");
    assert_eq!(t.tx_type, "ethereumTransaction");
    assert_eq!(t.payer, "0.0.10415063");
    assert_eq!(t.charged_fee_tinybar, 143_265);
    assert_eq!(t.result, "WRONG_NONCE");

    // All six were matched field-for-field against mirror REST.
    let types: Vec<_> = block
        .transactions
        .iter()
        .map(|t| t.tx_type.as_str())
        .collect();
    assert_eq!(
        types,
        [
            "ethereumTransaction",
            "cryptoTransfer",
            "cryptoTransfer",
            "cryptoApproveAllowance",
            "cryptoTransfer",
            "cryptoTransfer"
        ]
    );
    // value conservation holds on every result's transfer list
    for tx in &block.transactions {
        let sum: i64 = tx.transfers.iter().map(|l| l.amount).sum();
        assert_eq!(sum, 0, "transfer legs must conserve value");
    }
}
