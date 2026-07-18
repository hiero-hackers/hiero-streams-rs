# @hiero-hackers/streams-node

Node.js bindings for [`hiero-streams`](https://github.com/hiero-hackers/hiero-streams-rs)
— parse and cryptographically verify Hedera consensus streams (v6 record
files and HIP-1056 block streams) from JavaScript, backed by the Rust
core.

The binding is a thin JSON-over-FFI layer: functions take `Buffer`s and
return **JSON strings** in exactly the same golden shape the Rust
library, CLI, and tests produce (a differential test asserts that
equality). Reach for it when you want one audited implementation shared
across languages; for raw throughput, use the Rust crate directly (the
JSON crossing costs more than the parse — see the main README's
benchmark).

## Install

Published on the GitHub Packages npm registry with prebuilt binaries for
Linux (x64/arm64), macOS (x64/arm64), and Windows (x64) — no Rust toolchain
needed. GitHub's registry requires a `read:packages` token even for public
packages:

```sh
npm config set @hiero-hackers:registry https://npm.pkg.github.com
npm config set //npm.pkg.github.com/:_authToken "$(gh auth token)"
npm install @hiero-hackers/streams-node
```

## API

```js
const b = require("@hiero-hackers/streams-node");

// Parse — returns a JSON string; JSON.parse on the JS side.
const record = JSON.parse(b.parseRecordFileJson(rcdGzBuffer)); // v6 .rcd[.gz]
const block  = JSON.parse(b.parseBlockJson(blkGzBuffer));      // HIP-1056 .blk[.gz]

// v6 verification (low level).
const hashHex = b.recordFileHashHex(rcdGzBuffer);               // SHA-384, hex
const ok = b.verifyNodeSignature(hashHex, sigBuffer, pubKeyHex); // one node's RSA sig → bool

// Block-era verification — the block's in-band proof (merkle root,
// hinTS threshold signature, Schnorr/WRAPS suffix). Returns per-check
// JSON; `.valid` is the overall verdict.
const proof = JSON.parse(b.verifyBlockProofJson(blkGzBuffer));
// A non-genesis block needs the genesis block (carrying the ledger-ID
// publication) as the second argument:
const proof467 = JSON.parse(b.verifyBlockProofJson(block467Buffer, genesisBuffer));
```

Every function throws on malformed *inputs* (bad key, truncated file);
a well-formed-but-invalid signature or proof returns `false` /
`{"valid": false, ...}` rather than throwing — invalid input and
invalid proof are distinct outcomes.

Large integers (block number, fees, transfer amounts) are strings in
the JSON, because they exceed JavaScript's safe-integer range.

## Building from source

Requires a Rust toolchain and `protoc` (`brew install protobuf`):

```sh
npm install
npm run build   # napi build --release --platform
npm test        # differential test against the bundled fixtures
```

## License

Apache-2.0.
