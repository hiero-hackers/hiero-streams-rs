// Differential test from the JS side: the binding must return exactly
// the golden shape the Rust tests and CLI agree on.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const binding = require("./index.js");

const golden = JSON.parse(
    readFileSync("../../tests/fixtures/golden-v6.json", "utf8"),
);
let checked = 0;
for (const [name, expected] of Object.entries(golden)) {
    const bytes = readFileSync(`../../tests/fixtures/v6/${name}`);
    const actual = JSON.parse(binding.parseRecordFileJson(bytes));
    const a = JSON.stringify(actual, Object.keys(actual).sort());
    if (JSON.stringify(actual) !== JSON.stringify(JSON.parse(JSON.stringify(expected)))) {
        // compare structurally, key order independent
        const canon = (v) => JSON.stringify(sortKeys(v));
        function sortKeys(v) {
            if (Array.isArray(v)) return v.map(sortKeys);
            if (v && typeof v === "object")
                return Object.fromEntries(Object.entries(v).sort().map(([k, x]) => [k, sortKeys(x)]));
            return v;
        }
        if (canon(actual) !== canon(expected)) {
            console.error(`DIVERGENCE in ${name}`);
            process.exit(1);
        }
    }
    checked += 1;
}
const hash = binding.recordFileHashHex(
    readFileSync("../../tests/fixtures/v6/2022-07-13T08_46_11.304284003Z.rcd.gz"),
);
if (!/^[0-9a-f]{96}$/.test(hash)) {
    console.error("bad hash output"); process.exit(1);
}

// Block parsing must be exported and era-consistent (this export was
// once silently dropped by a stale generated index.js — keep this).
const previewParsed = JSON.parse(binding.parseBlockJson(
    readFileSync("../../tests/fixtures/block-preview/000000000000000000000000000104356004.blk.gz"),
));
if (previewParsed.format !== "block-stream" || previewParsed.blockNumber !== "104356004") {
    console.error("parseBlockJson shape broke:", previewParsed.blockNumber);
    process.exit(1);
}

// Block-proof verification: genesis self-bootstraps (Schnorr path),
// a later block needs the genesis passed explicitly (WRAPS path).
const genesis = readFileSync("../../tests/fixtures/tss/0.blk.gz");
const genesisProof = JSON.parse(binding.verifyBlockProofJson(genesis));
if (genesisProof.valid !== true || genesisProof.proofPath !== "aggregate-schnorr"
    || genesisProof.schnorr?.valid !== true) {
    console.error("genesis block proof did not verify:", genesisProof);
    process.exit(1);
}
const wrapsBlock = readFileSync("../../tests/fixtures/tss/467.blk.gz");
const wrapsProof = JSON.parse(binding.verifyBlockProofJson(wrapsBlock, genesis));
if (wrapsProof.valid !== true || wrapsProof.proofPath !== "wraps-compressed-proof"
    || wrapsProof.wraps?.groth16Valid !== true) {
    console.error("WRAPS block proof did not verify:", wrapsProof);
    process.exit(1);
}
let missingBootstrapRejected = false;
try {
    binding.verifyBlockProofJson(wrapsBlock);
} catch (err) {
    missingBootstrapRejected = /ledger-ID publication/.test(String(err));
}
if (!missingBootstrapRejected) {
    console.error("missing bootstrap must be a clear error");
    process.exit(1);
}

// verifyNodeSignature: the low-level v6 signature check. This triple was
// extracted from the bundled fixtures (record_file_hash + the .rcd_sig's
// file_signature + node 0.0.3's key from test-v6-sidecar-4n.bin) — the
// same values the Rust record_verify test asserts.
const V6_HASH =
    "ed518c8d05f470d4540db35ea8665ab158f9aeb0bcaa3332d171c1efba119da52c1ee510df599269b022d963d4d1e474";
const V6_SIG = Buffer.from(
    "b0d5d5667661e21bee8d538066aacebbfe8f0325c6b34e1344920339ee42a098d7cae2177bfa7dd7192a9d4d300277514fa9ed51f0a0977491d5606db6e86980ae89a893d9e48a7a9b937e787bf8dd6c4cdff04bef503fb59412ebf5206d1fe7592af0568bb4ba8ccb693bf17832d7af0ab1acad37cda8f8216336ae4864312ceec884eb27a1b87ce09cbb50501f1402cfaf189f79fcd25ca040b09df4bc29e15faa081ab6631918a00a393e9b23fc2d835dd32d9cd4dfe9e7036e82ef0de7da9c692708eb0a9f006c4ccff216097a5090979aad4c3f8487a62c896dd120473a8dc590c3c7d96ee8964d62b206063df9a18b1cc83628642152d7943ba2474ce494d8a34c4a284ab3116d6437dacf15a5f8ebe1c0558231506b422323a3b24db2fa1b9b7b0ca693391e3faacab90ac8ad46509bce590a37fbc80cb6b950d0a783a2cb80c9d72598d724586d6bbe83eac7f151ce99969afcf580fbbec57900f1c76a1f8806974ba554e08d010d4695594e2fd5a18038732486f44332e8988b33e3",
    "hex",
);
const V6_KEY =
    "308201a2300d06092a864886f70d01010105000382018f003082018a0282018100c1a0ff5d2372b53d12d12bb87dd03f5e3427e0cee1d3c898bbd320c4b3dd17257944ea39a07f5344d9abfcdd50214072f1bbc12173fe7933d032c7d210734cc92d24be22b44cf50c2aa06f19bcd75180dc3e8dedd5ffcac02bf98721df9c3e79f20e9942cac9328b99160afea44d42c87b0147f3f29567085ed3f841dbe37aba35a2c5446bc638c62c703a6f680fa0601bfe7c6254e9fe2f471670ecdcca26128716a08f4141595ec0c4ac7ae589f37deede17480ecc1500f88335d0e33929725e8e4e775f3e4aa44c867bc86d3bf6d7165a4b766dd4ceb622221634a0a3d82840800b5b3e540640ea2f8c5749c3a6a0e0c474515c3f0ed9aadab8f84423a8954fd7f4e40b73125aeced4f791dba5052e3f5b3191a430f9b2dd30e4071cc54280c830da0d1e0dd54300c243ef08d9f81b3a90373f10910b6f4975bb2d861273993221e42b82b5af823267f79de90a7221129f0423724f9208a4ca15a73458c555e08e015db9d77c884acacaf4971d3854ea7bbdd9cfaf49df852c11473e96fa10203010001";

if (binding.verifyNodeSignature(V6_HASH, V6_SIG, V6_KEY) !== true) {
    console.error("verifyNodeSignature: valid signature must verify");
    process.exit(1);
}
// A wrong hash must not verify (and must not throw).
const badHash = "00" + V6_HASH.slice(2);
if (binding.verifyNodeSignature(badHash, V6_SIG, V6_KEY) !== false) {
    console.error("verifyNodeSignature: wrong hash must fail");
    process.exit(1);
}
// A malformed key is an error, not a silent false.
let badKeyThrew = false;
try {
    binding.verifyNodeSignature(V6_HASH, V6_SIG, "not-hex");
} catch {
    badKeyThrew = true;
}
if (!badKeyThrew) {
    console.error("verifyNodeSignature: malformed key must throw");
    process.exit(1);
}

console.log(`binding differential: ${checked} files match the golden shape; hash=${hash.slice(0, 16)}…`);
console.log(`block proofs: genesis schnorr ✓ (${genesisProof.schnorr.signerCount}/${genesisProof.schnorr.totalNodes} signers), block 467 wraps ✓, missing-bootstrap rejected ✓`);
console.log("verifyNodeSignature: valid ✓, wrong-hash rejected ✓, malformed-key throws ✓");
