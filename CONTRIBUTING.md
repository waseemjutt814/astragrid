# Contributing

This project accepts only changes that improve executable behavior, verifiable quality, or
operator documentation.

## Local Checks

Run these before opening a pull request:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
cargo doc --workspace --no-deps
```

## Code Rules

- Prefer deterministic state transitions over hidden background behavior.
- Keep security-sensitive logic in small modules with tests.
- Do not add placeholder integrations.
- Do not add an AI provider until the request/response evidence contract exists.
- Keep CLI output machine-readable when a command mutates or verifies operational state.

## Pull Request Evidence

Every non-trivial pull request should include:

- The user or operator problem being solved.
- The code path changed.
- Tests or manual verification commands.
- Known limitations, if any.
