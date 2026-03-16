# bip39key

Deterministic GPG key generation from BIP39 seed phrases.

Given the same mnemonic phrase, passphrase, user ID, and timestamp, `bip39key` always produces the same GPG key. This lets you derive your GPG identity from a BIP39 seed phrase that you can back up as 12 or 24 words, instead of managing opaque key files.

## Security warning

All keys (primary + subkeys) are derived from a single seed phrase. If the mnemonic is compromised, **all derived keys are compromised**. Protect your seed phrase accordingly.

The derivation is cryptographically sound (PBKDF2 + HKDF + Ed25519/Cv25519), but the security of the generated keys depends entirely on the secrecy and entropy of your mnemonic.

## Installation

### With Nix

```
nix develop
cargo build --release
```

### Without Nix

System dependencies: [Nettle](https://www.lysator.liu.se/~nisse/nettle/) (cryptographic library), pkg-config, libclang.

On Debian/Ubuntu:
```
apt install nettle-dev pkg-config libclang-dev
```

Then:
```
cargo build --release
```

The binary is at `target/release/bip39key`.

## Usage

```
bip39key --phrase <PHRASE> --userid <USERID> --timestamp <TIMESTAMP> [OPTIONS]
```

### Options

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--phrase` | `-P` | yes | BIP39 mnemonic phrase (12 or 24 words) |
| `--passphrase` | `-p` | no | BIP39 passphrase (default: empty) |
| `--userid` | `-u` | yes | User ID, e.g. `"Name <email>"` |
| `--timestamp` | `-t` | yes | Key creation time as Unix seconds |
| `--no-subkeys` | | no | Generate primary key only |

### Examples

Generate a full key (primary + signing + encryption + authentication subkeys):

```
bip39key \
  --phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --userid "Alice <alice@example.com>" \
  --timestamp 1700000000
```

Generate a primary-only key (certification capability only):

```
bip39key \
  --phrase "your twelve word mnemonic phrase here" \
  --userid "Alice <alice@example.com>" \
  --timestamp 1700000000 \
  --no-subkeys
```

Import into GPG:

```
bip39key ... | gpg --import
```

## How it works

```
BIP39 Mnemonic + Passphrase
  |
  v
PBKDF2-HMAC-SHA512 (2048 iterations)     [BIP39 standard]
  |
  v
64-byte seed
  |
  v
HKDF-SHA256 (with distinct info strings)  [RFC 5869]
  |
  +---> "ed25519 primary key"          --> Ed25519 primary key    [C]
  +---> "ed25519 signing subkey"       --> Ed25519 signing subkey [S]
  +---> "cv25519 encryption subkey"    --> Cv25519 encryption subkey [E]
  +---> "ed25519 authentication subkey"--> Ed25519 auth subkey    [A]
```

The key material is fully deterministic: same inputs always produce the same key fingerprints. Signature packets contain random salt (added by the OpenPGP library for security), so the full armored output varies between runs, but the underlying keys are identical.

## License

GPL-3.0-only
