<!--
Thanks for contributing! Please complete every section. A PR with a vague
description is much harder to review on a security-sensitive protocol library.
-->

## What does this change?

<!-- One paragraph. Describe the behaviour change, not the diff. -->

## Why is it correct?

<!-- Reference: HAP spec section, aiohomekit behaviour, captured test vector. -->

## How was it tested?

- [ ] Unit tests added or updated
- [ ] Test vectors captured from aiohomekit (required for any wire-protocol change)
- [ ] Manual test against a real HomeKit accessory (if applicable)
- [ ] `cargo fmt --all`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`

## Crypto checklist (delete if not applicable)

- [ ] This PR touches `hap-crypto/` or otherwise changes Pair Setup / Pair Verify wire bytes
- [ ] I have labelled the PR `crypto`
- [ ] I have included aiohomekit / HAP-spec vectors that prove the change byte-for-byte
- [ ] I have added negative-path tests (wrong setup code, tampered signature, replay, out-of-order state) where applicable

> This project does not gate crypto releases on external review (see CLAUDE.md).
> Cross-verification and interop testing carry that weight — be thorough.

## Related issues / milestones

<!-- e.g. "Part of #N (Milestone 1)" -->
