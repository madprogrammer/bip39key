# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

This project uses a Nix flake for development dependencies. All cargo commands must be run inside the Nix dev shell:

```sh
nix develop -c cargo build          # debug build
nix develop -c cargo build --release # release build
nix develop -c cargo test            # run all tests
nix develop -c cargo test known_vector  # run a single test by name
```

System dependencies (provided by Nix): nettle, pkg-config, libclang.

## Architecture

Deterministic GPG key generator that derives Ed25519/Cv25519 OpenPGP keys from BIP39 seed phrases.

**Cryptographic pipeline:**
```
BIP39 mnemonic + passphrase
  → PBKDF2-HMAC-SHA512 (BIP39 standard) → 64-byte seed
  → HKDF-SHA256 (distinct info strings per key) → 32-byte key material
  → OpenPGP certificate (Ed25519 primary + Ed25519 signing + Cv25519 encryption + Ed25519 auth subkeys)
```

**Two modules + thin CLI driver:**

- `src/derive.rs` — BIP39 parsing and HKDF key derivation. No OpenPGP knowledge. The HKDF info string constants (`INFO_PRIMARY`, `INFO_SIGNING`, etc.) define the derivation paths and must never change.
- `src/cert.rs` — OpenPGP certificate assembly using sequoia-openpgp. Takes raw `[u8; 32]` key material and builds `Cert` objects. Signing subkeys require an embedded back-signature (`PrimaryKeyBinding`).
- `src/main.rs` — CLI (clap). Parses args, calls derive + cert, prints armored output.

## Key Constraints

- **sequoia-openpgp is pinned to ~1.16.0** because newer versions (1.17+) add random salt to signatures per RFC 9580, breaking output determinism. Key material is always deterministic; signatures are not (they contain `salt@notations.sequoia-pgp.org`).
- The `sign_subkey_binding`/`sign_primary_key_binding` methods require `Key<PublicParts, PrimaryRole>`, not `SecretParts`. Convert via `.parts_into_public()`.
- `Key4::import_secret_ed25519` for subkeys needs explicit type annotation: `Key4::<key::SecretParts, key::SubordinateRole>::import_secret_ed25519(...)`.
- Tests use the BIP39 test vector mnemonic "abandon abandon ... about" (12 words). The `known_vector_primary_key` test locks the derivation output to a hardcoded byte array — if the pipeline changes, this test must be updated intentionally.
