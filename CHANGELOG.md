# Changelog

## 0.1.1

- Update signal-hook from 0.3.18 to 0.4.6, retaining the existing signal handling API and cancellation behavior.
- Add GitHub Actions CI for Rust formatting, Clippy, regression tests, release/native builds, and offscreen Qt checks.
- Run CI on master pushes, version tags, pull requests, and manual dispatch, using an Arch Linux container and a commit-pinned checkout action with read-only permissions.

## 0.1.0

- Initial Omarchy-themed pinentry for rbw with native locked-memory password fields, authenticated socket transport, and process hardening.
- Add desktop, offscreen Qt, and isolated rbw integration tests.
- Limit passwords to one Assuan data line to avoid truncation by rbw 1.15.
