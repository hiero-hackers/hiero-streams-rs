# Contributing to hiero-streams

Thanks for your interest. This crate parses and cryptographically
verifies Hedera consensus streams; correctness is anchored to the
network itself, so the contribution bar centers on *not breaking that
anchor*.

## Getting started

Prerequisites:

- **Rust 1.82+** (the crate's MSRV, in `Cargo.toml` / enforced by CI)
- **protoc** — `brew install protobuf` / `apt-get install protobuf-compiler`

Build and test across the feature matrix CI uses:

```sh
cargo test                                     # default features
cargo test --no-default-features               # pure-library config
cargo test --features block-proofs --release   # proof crypto (release: pairings are slow in debug)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --features block-proofs --all-targets -- -D warnings
```

New to the code? Read [`docs/CODE-TOUR.md`](docs/CODE-TOUR.md) (module
map, byte-trace paths, and which test pins which contract) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### Pre-commit hook (recommended)

A committed hook runs the two fastest CI gates — `cargo fmt --check`
and `cargo clippy -D warnings` — locally before each commit, so those
never fail in CI. Enable it once per clone:

```sh
git config core.hooksPath .githooks
```

It only runs when Rust or Cargo files are staged, and you can skip it
for a work-in-progress commit with `git commit --no-verify`. The full
feature matrix, test suites, supply-chain checks (`cargo-deny`),
fuzzing, and the Node binding still run in CI — the hook is a fast
pre-flight, not a replacement.

## What the tests guard (read before changing behavior)

Several tests exist specifically to catch silent changes to
network-anchored contracts. If your change touches these, the failure
is the point — don't paper over it:

- **`tests/record_snapshot.rs` / `golden-v6.json`** — the canonical JSON
  output shape. Changing parsed fields requires regenerating the golden
  file (see its note) *and* justifying the change.
- **`tests/record_mirror_differential.rs`** — parsed output must match the
  mirror node's independent decode of the same mainnet files.
- **`tests/block_proof_differential.rs`** — block-proof verification must
  agree check-for-check with `hiero-block-verifier-js`; tamper tests
  must fail at the exact expected check.
- **`tests/block_chain.rs`, `tests/record_verify.rs`, the schema test
  in `src/cli/etl/parquet.rs`** — continuity, real-crypto verification,
  and the Parquet dataset contract.

Security-sensitive changes (anything under `src/block/proof/` or `src/record/verify.rs`)
should add a test that fails without the change — see the
empty-bitvector forgery test in `src/block/proof/schnorr.rs` for the
expected rigor.

## Conventions

- **rustfmt + clippy clean** (`-D warnings`) — CI rejects otherwise.
- **Dependency frugality is a policy.** Hand-rolled date math,
  percent-encoding, and CLI parsing exist because the dependency would
  be larger than the code. Justify any new dependency against that bar;
  the proof crypto (arkworks) is deliberately behind an off-by-default
  feature for this reason. New dependencies must also clear
  [`deny.toml`](deny.toml) — a permissive license (no copyleft), no
  open advisories, no wildcard versions — which CI enforces via
  `cargo deny check`. Run it locally with `cargo deny check` if you add
  one.
- **The library does no I/O.** Only the `fetch`-gated CLI touches the
  network. Keep that boundary.
- Vendored protos (`proto/`, `proto-hapi/`) are reviewed copies, not
  submodules — record the source commit when updating `proto-hapi/`.
- **Some dependency versions are load-bearing** and are held by
  [`dependabot.yml`](.github/dependabot.yml), which explains each:
  **arkworks stays on 0.4** (its 0.4 `expand_message_xmd` and wire
  format are what make proof verification byte-match the network —
  0.5+ would silently break it); **prost, sha2, and napi majors are
  manual** (they regenerate proto code, shift the RustCrypto/`rsa`
  pairing, or change the binding ABI). Patch bumps flow automatically;
  those minors/majors are deliberate, tested upgrades — not unattended
  ones.

## Pull requests

1. Fork, branch from `main`, keep the change focused.
2. Ensure the full test matrix and lints above pass locally.
3. Open a PR against `main` with a clear description of what and why.
   CI must be green; a maintainer review is required before merge.

### Developer Certificate of Origin

Contributions are accepted under the [DCO](https://developercertificate.org/):
sign off each commit to certify you have the right to submit it under
the project's Apache-2.0 license.

```sh
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line.

## Releasing (maintainers)

Releases publish to [crates.io](https://crates.io/crates/hiero-streams) and
the Node binding (`@hiero-hackers/streams-node`, prebuilt binaries) to the
GitHub Packages npm registry, from CI, never from a laptop. The crates.io
token lives only as the org-owned `TOKEN_STREAMS_RS` repository secret, so
no maintainer needs it locally; npm publishing uses the workflow's own
`GITHUB_TOKEN` (no standing secret at all). To cut a release:

1. Bump `version` in `Cargo.toml` **and** `bindings/node/package.json`
   (lockstep), and land it on `main`.
2. Tag the release commit with a **matching** `v` tag and push it:

   ```sh
   git tag -s v0.1.0 -m "hiero-streams 0.1.0"
   git push origin v0.1.0
   ```

3. The [`release.yml`](.github/workflows/release.yml) workflow checks the tag
   equals both versions, publishes the crate, builds the binding on all five
   platforms, and publishes the npm package. Watch it in the Actions tab.

The tag must equal the crate and binding versions — a mismatch fails the
workflow instead of publishing the wrong one. The crate and npm halves are
independent, so a re-run publishes whichever half is still missing. A manual
`workflow_dispatch` run is the fallback if you ever need to publish without
a tag.

The crate is owned on crates.io by the
[LFDT bot account](https://crates.io/users/lfdt-bot) — institutional custody
under Linux Foundation Decentralized Trust, so ownership never rests with a
single personal account. Owner changes, and migrating crates.io auth to
[Trusted Publishing](https://crates.io/docs/trusted-publishing) (OIDC,
which would retire `TOKEN_STREAMS_RS`), go through LFDT: only a crate owner
can act on the crate's Settings page.

## License

By contributing, you agree that your contributions are licensed under
the [Apache License 2.0](LICENSE).
