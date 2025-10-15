# omarchy-cert-tui

Interactive terminal user interface (TUI) and supporting crates for discovering, inspecting, and organising X.509 certificates. The project is split into three crates:

| Crate | Purpose |
|-------|---------|
| `omarchy-cert-core` | Blocking/async helpers for fetching remote certificates, parsing local stores (PEM, PKCS#7, PKCS#12, Java keystores/truststores) and discovering files. |
| `omarchy-cert-cli`  | Minimal CLI wrapper around the core crate. Handy for quick scripting or piping JSON. |
| `omarchy-cert-tui` (binary `cerTUI`) | Full-screen TUI built with `ratatui`/`crossterm`, featuring history, filtering, password prompts for protected stores, and mouse support. |

---

## Prerequisites

* Rust toolchain (`rustup` recommended).
* `openssl` CLI in your `PATH` (used for remote fetches and PKCS conversions).
* Optional:
  * `keytool` (Java) for reading keystores/truststores.
  * A terminal with mouse support (most modern terminals qualify).

Clone and build:

```bash
git clone <repo-url>
cd omarchy-cert-tui
cargo build
```

---

## Running the TUI

```bash
cargo run --bin cerTUI
```

### Layout Overview

```
┌ Target Input ──────────────────────────────────────────────┐
│ [T] target (host:port or path)                             │
└────────────────────────────────────────────────────────────┘
┌ History (full width) ──────────────────────────────────────┐
│ [H] history                                                 │
│    mycert.pem [3] /home/user/certs — Loaded 3 cert(s) …    │
│    truststore.p12 [5] /etc/ssl        — Password required  │
└────────────────────────────────────────────────────────────┘
┌ Certificates (full width) ─────────────────────────────────┐
│ [C] certificates — Local mycert.pem — showing 3/3 certs     │
│ Index  Subject            Issuer           …                │
│ 0      CN=my.pc.com …     CN=My Root CA … …                 │
└────────────────────────────────────────────────────────────┘
┌ Filter Bar ────────────────────────────────────────────────┐
│ [/] filter — history: Press / to search history            │
└────────────────────────────────────────────────────────────┘
┌ Status (wraps) ────────────────────────────────────────────┐
│ Loaded 3 cert(s) from /home/user/certs. …                  │
│ Sort: subject (ascending)   Timeout: 5s   2025-02-11 … UTC │
└────────────────────────────────────────────────────────────┘
┌ Shortcuts (full width) ────────────────────────────────────┐
│ Enter/Tab/Ctrl+F/…                                          │
└────────────────────────────────────────────────────────────┘

Modals overlay the above:

* Password prompt – centered, captures keyboard input only.
* Certificate details – shows metadata + PEM; clicking the PEM copies it.
* Fullscreen PEM – any key exits.
* Find dialog – selects a root for file discovery.
```

---

## Keyboard & Mouse Reference

### Global Keys

| Key | Action |
|-----|--------|
| `q` | Quit (persists history first). |
| `Tab` / `Shift+Tab` | Cycle focus between Target → History → Certificates. |
| `/` | Starts filter mode on focused pane (history or certificates). |
| `Ctrl+F` | Open “Find certificates” dialog (recursively scans a directory). |
| `Ctrl+R` | Refresh the currently selected entry (remote re-fetch or local re-read). |
| `Ctrl+L` | Clear history. |
| `e` | Enter target edit mode (retains current value). |

> While a filter is active (`/`), pane-switch shortcuts (`t`, `h`, `c`) are disabled until you press `Enter` or `Esc`, mirroring the target editor behaviour.

### Pane-Specific Keys

**Target Input**

| Key | Action |
|-----|--------|
| `Enter` | Toggle edit mode. If editing, submit (clears field for keyboard-entered toggles). |
| `Esc` | Cancel editing, restore last selection. |
| `Tab` (editing) | Path autocomplete. |

**History Panel**

| Key | Action |
|-----|--------|
| `Up` / `Down` | Move selection. |
| `Enter` | Focus target input (data copied but not cleared). |
| `Delete` / `x` | Remove entry. |
| `s`, `i`, `n`, `d`, `o` | Sort certificates (Subject, Issuer, Not After, Days Left, Chain order). |

**Certificates Panel**

| Key | Action |
|-----|--------|
| `Up` / `Down` | Change highlighted certificate. |
| `Enter` | Open details modal. |
| Sorting keys | Same as history panel. |

**Filter Mode (`/`)**

| Key | Action |
|-----|--------|
| `Enter` | Apply filter & exit. |
| `Esc` | Clear filter & exit. |
| `Backspace` | Delete last character. |
| `[text]` | Append character (no Ctrl/Alt). |

**Password Dialog**

| Key | Action |
|-----|--------|
| `Enter` | Submit password and retry load. |
| `Esc` | Cancel (entry remains locked). |
| `Backspace` | Delete last character. |

### Mouse Support

| Action | Behaviour |
|--------|-----------|
| Click target input | Enter edit mode (value retained). |
| Click history row | Focus history, select entry. |
| Click certificate row | Focus certificate pane, select row, open details modal. |
| Click filter bar | Activate filter for the active pane. |
| Click PEM block in details | Copy PEM to system clipboard. |
| Scroll wheel on history / certificates | Scroll within the respective list. |
| Click inside password dialog | (Ignored; keyboard only). |
| Click during fullscreen PEM | No-op (press any key to exit). |

Mouse support relies on terminal reporting `MouseEvent`s; ensure you run the app in a capable terminal (e.g. Alacritty, Kitty, WezTerm, GNOME Terminal).

---

## Fetching & File Support

* **Remote** – uses `openssl s_client -showcerts` with optional SNI.
* **Local** – understands PEM (`.pem`, `.crt`, `.cer`, `.cert`), PKCS#7 (`.p7b`, `.p7c`, `.pkcs7`), PKCS#12 (`.p12`, `.pfx`, `.pkcs12`), and Java keystores/truststores (`.jks`, `.jceks`, `keystore`, `truststore`). Password prompts appear when necessary (`OMARCHY_CERT_PASSWORD`, `OMARCHY_PKCS12_PASSWORD`, `OMARCHY_KEYSTORE_PASSWORD` env vars are used first).
* **Discovery** – `Ctrl+F` opens a dialog to scan a directory tree (uses `find` + known extensions).

Locked entries are indicated in history, and the filter bar hints at unlocking when appropriate.

---

## CLI Usage

```bash
# Inspect remote host
cargo run -p omarchy-cert-cli -- inspect example.com:443 --sni example.com

# JSON output
cargo run -p omarchy-cert-cli -- inspect-json example.com:443
```

---

## Packaging & Omarchy Integration

### Install the TUI Binary

```bash
cargo install --path crates/tui --locked
# Binary ends up in ~/.cargo/bin/cerTUI
```

### Add an Omarchy Launcher Entry

1. Create `~/.config/omarchy/launcher.d/cert-tui.desktop` (adjust path if your Omarchy build differs):

   ```ini
   [Desktop Entry]
   Name=Certificate Inspector (TUI)
   Comment=Inspect local and remote certificates
   Exec=/home/<user>/.cargo/bin/cerTUI
   Type=Application
   Terminal=true
   Categories=Utility;Security;
   ```

2. Refresh the Omarchy launcher/menu (log out/in or run the appropriate Omarchy refresh command).

### Keyboard Shortcut (example using Omarchy’s shortcut manager)

1. Open Omarchy Settings → Keyboard → Shortcuts.
2. Add a custom shortcut:
   * Name: `Certificate Inspector`
   * Command: `/home/<user>/.cargo/bin/cerTUI`
   * Binding: e.g. `Super+Shift+C`
3. Apply changes.

### Running as a systemd service (optional)

*.service* units are not required for interactive TUIs, but you can wrap the binary in a script or `.desktop` file for launcher integration (as above). For headless usage, rely on the CLI crate instead.

---

## Development Notes

* The workspace uses `ratatui` + `crossterm` + `arboard` for rendering, terminal input, and clipboard support.
* `cargo check`, `cargo fmt`, and `cargo clippy` keep code healthy across crates.
* History persists between runs via JSON in the user’s config directory (see `history_display_path()` in the code).
* Password-protected stores cache failure reason to help you troubleshoot.

---

## Preparing a GitHub Repository

1. **Register or reset GitHub password**
   * New account:
     1. Visit <https://github.com/signup>.
     2. Enter email, pick a username & password, verify email, complete onboarding.
   * Forgot password:
     1. Visit <https://github.com/password_reset>.
     2. Provide your email/username, follow the emailed link to set a new password.

2. **Initialise the local repo (if not already)**

   ```bash
   git init
   git add .
   git commit -m "Initial commit: certificate TUI"
   ```

3. **Create a GitHub repository**
   * Go to <https://github.com/new>.
   * Choose owner, repository name (`omarchy-cert-tui` recommended), keep it empty (no README).
   * Click “Create repository”.

4. **Connect and push**

   ```bash
   git remote add origin git@github.com:<user>/omarchy-cert-tui.git
   # or https://github.com/<user>/omarchy-cert-tui.git
   git branch -M main
   git push -u origin main
   ```

5. **Subsequent updates**

   ```bash
   git add .
   git commit -m "Describe changes"
   git push
   ```

For SSH pushes ensure you have an SSH key registered in GitHub (`Settings → SSH and GPG keys`). For HTTPS pushes, GitHub requires a personal access token instead of a password – generate one at <https://github.com/settings/tokens>.

---

## Troubleshooting

* **Clipboard errors** – Ensure your environment provides clipboard access (Wayland sessions may require `wl-copy`/`wl-paste`; alternatively disable mouse Copy).
* **Password prompts looping** – Check environment variables for outdated passwords; Masked input is case-sensitive.
* **Keystore parsing** – Ensure `keytool` is installed and that the keystore is readable by the current user.

Happy certificate hunting!
