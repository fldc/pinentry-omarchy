# Desktop and rbw validation

Validated on 2026-11-10 with the rebuilt 0.1.0 frontend and package revision 3.
Environment: Arch Linux, Hyprland 0.57.1-2, Quickshell 0.3.2.r7.g2b4501a-7,
Qt 6.12.0-3, and rbw 1.15.0-2.

## Passing checks

- `cargo test --locked`: 29 enabled tests passed; desktop test excluded by default.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo fmt --check` and `git diff --check`: passed.
- `bin/test-native`: offscreen Qt overflow, repeat, recovery, and delivery checks passed.
- `cargo test --locked --test live -- --ignored --test-threads=1`: passed.
- `python3 tests/rbw.py`: passed against the real installed rbw/rbw-agent binaries.
- `bin/package --nodeps --force --nosign`: built `pinentry-omarchy-0.1.0-3-x86_64.pkg.tar.zst` with Rust and offscreen native checks enabled.

The desktop suite covered password delivery, Escape cancellation, confirmation,
repeat mismatch/recovery, interaction timeout, focus-loss erasure/cancellation,
memory-lock failure, rbw-style closed command stdin with unlimited timeout,
process memory protections, environment isolation, and caller-disconnect cleanup.

The rbw fixture used a temporary encrypted local vault with generated keys,
a dummy login entry, and a short UTF-8 master password containing `%`.
It verified cancelled unlock, wrong-password retry followed by successful unlock,
`unlocked`, repeated unlock without another prompt, `list`, `get`, `lock`, and
automatic unlock when retrieving a locked entry. The isolated agent was stopped
and its temporary runtime, configuration, cache, and data files were removed.

## Compatibility fix found during testing

An isolated protocol probe confirmed that rbw 1.15 consumes only the first
Assuan data line and ignores a suffix on the next line. Password input and
backend delivery now enforce a single data line: at most 996 escaped bytes.
Each `%`, CR, or LF costs three encoded bytes. Oversized input blocks submission
until cleared and re-entered; the backend independently refuses oversized secrets
before returning data. Rust and offscreen Qt regressions cover this behavior.

## Scope

The desktop suite and initial rbw integration exercised the rebuilt checkout
executable. Package 0.1.0-3 was subsequently installed, and the isolated rbw
suite passed again with `PINENTRY_TEST_BINARY=/usr/bin/pinentry-omarchy`.
`pacman -Qkk pinentry-omarchy` reported zero altered files; the executable and
native UI/startup libraries were confirmed root-owned with mode 755.
The user's rbw configuration remained set to `pinentry`, and their real vault
remained locked. No real account credentials or vault entries were used.

The dummy fixture validates local vault operations. Server login, registration,
sync, and 2FA were not exercised. The startup-loader limitation described in
SECURITY.md remains; passing these checks is not an independent security audit.
