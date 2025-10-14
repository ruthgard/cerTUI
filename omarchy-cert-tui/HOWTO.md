
# omarchy-cert-tui (starter)

A Neovim-style, event-driven TUI/CLI starter to inspect remote TLS certificates and show expiry,
built for Linux (works great in Omarchy). It **uses the system `openssl`** to grab the presented chain, then parses
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
- A UTF-8 terminal (xterm-compatible) for mouse support

## Build

```bash
# from repo root
cargo build
```

## Run (CLI)

```bash
# Inspect remote endpoint
cargo run -p omarchy-cert-cli -- inspect example.com:443
# With explicit SNI (optional)
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
# Release build (static-ish depending on your toolchain)
cargo build --release
```

Artifacts in `target/release/`:
- `omarchy-cert-cli`
- `omarchy-cert-tui`

## Notes

- This starter shells out to `openssl s_client` for parity with real-world chains.
  You can swap to native TLS libraries later.
- Parsing uses `x509-parser` and `pem` crates.
- The code is structured so the **core** crate remains UI-agnostic.
