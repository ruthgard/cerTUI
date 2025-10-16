
# omarchy-cert-tui (starter, fixed)

A Neovim-style, event-driven TUI/CLI starter to inspect remote TLS certificates and show expiry,
built for Linux (works in Omarchy). It **uses the system `openssl`** to grab the presented chain, then parses
certificates locally.

## Features (MVP)

- CLI: `inspect` a `host:port` and print leaf expiry + chain subjects
- TUI: Text input for `host:port`, press **Enter** to fetch; table with expiry, issuer, subject
- Parses PEM blocks from `openssl s_client -showcerts`
- No ncurses, modern TUI (ratatui + crossterm)
- Async tasks using tokio

> This is a starting point; extend with trust-store verification, local file parsing, watch list, etc.

---

## Prereqs

- Linux with:
  - Rust toolchain (`rustup`, `cargo`)
  - `openssl` CLI installed (e.g., `pacman -S openssl` or `apt-get install openssl`)

## Build

```bash
cargo build
```

## Run (CLI)

```bash
cargo run -p omarchy-cert-cli -- inspect example.com:443
cargo run -p omarchy-cert-cli -- inspect example.com:443 --sni example.com
```

## Run (TUI)

```bash
cargo run -p omarchy-cert-tui
```

- Type `example.com:443` and press **Enter**.
- Press `r` to re-fetch current host.
- Press `q` to quit.

## Packaging

```bash
cargo build --release
```

## Notes / Fixes

- Validity timestamps are stored as **epoch seconds** to avoid `chrono` serde issues.
- Added `sha2` dependency; using `pem::Pem::contents()` accessor.
- Removed `FromBer` import; simplified X.509 parsing.
