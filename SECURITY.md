# Security Policy

## Supported versions

`hiero-streams` is pre-1.0. Security fixes are applied to the latest
`0.x` release; there is no back-porting to earlier `0.x` versions.

| Version | Supported |
| ------- | --------- |
| latest `0.x` | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/hiero-hackers/hiero-streams-rs/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). If
you cannot use that, open a minimal public issue asking for a private
contact channel — without any exploit detail — and a maintainer will
respond.

Please include: the affected version or commit, a description of the
issue, and a proof of concept or reproduction if you have one.

We aim to acknowledge a report within a few days and to agree on a
coordinated disclosure timeline before any public detail is shared.

## Scope

This crate **parses and verifies attacker-controlled bytes** (consensus
stream files and their proofs), so the following are in scope:

- **Panics or crashes** on malformed input — the library contract is
  that its functions return `Result`, never panic, on any byte input.
- **Verification soundness** — any input that causes a forged or
  tampered file, signature, or block proof to be reported as valid
  (`verify_record_file`, `verify_block_proof`, and the `verify` CLI).
  This is the crate's core guarantee.
- **Resource exhaustion** from crafted input (decompression bombs,
  unbounded allocation).

Out of scope: the crate holds no private keys and performs no signing —
it is verification-only. Issues in third-party dependencies should be
reported upstream (we track advisories via `cargo audit` in CI).

## Disclosure

Fixed vulnerabilities are disclosed in the release notes and, where a
CVE applies, via a GitHub Security Advisory once a fixed version is
available.
