use anyhow::Result;
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF info strings for deterministic key derivation.
/// These MUST NOT change — they define the derivation paths.
pub const INFO_PRIMARY: &[u8] = b"ed25519 primary key";
pub const INFO_SIGNING: &[u8] = b"ed25519 signing subkey";
pub const INFO_AUTH: &[u8] = b"ed25519 authentication subkey";
pub const INFO_ENCRYPT: &[u8] = b"cv25519 encryption subkey";

/// Raw key material for building an OpenPGP certificate.
pub struct DerivedKeyMaterial {
    pub primary: [u8; 32],
    pub signing: [u8; 32],
    pub authentication: [u8; 32],
    pub encryption: [u8; 32],
}

/// Parse a BIP39 mnemonic and derive the 64-byte seed.
///
/// Checksum validation is skipped to allow flexibility with non-standard phrases.
pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<[u8; 64]> {
    let mnemonic = Mnemonic::parse_in_normalized_without_checksum_check(Language::English, phrase)?;
    Ok(mnemonic.to_seed_normalized(passphrase))
}

/// Derive 32 bytes of key material from a seed using HKDF-SHA256.
fn derive_key(seed: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Derive all key material (primary + 3 subkeys) from a BIP39 seed.
pub fn derive_all(seed: &[u8]) -> DerivedKeyMaterial {
    DerivedKeyMaterial {
        primary: derive_key(seed, INFO_PRIMARY),
        signing: derive_key(seed, INFO_SIGNING),
        authentication: derive_key(seed, INFO_AUTH),
        encryption: derive_key(seed, INFO_ENCRYPT),
    }
}

/// Derive only the primary key material from a BIP39 seed.
pub fn derive_primary_only(seed: &[u8]) -> [u8; 32] {
    derive_key(seed, INFO_PRIMARY)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn known_vector_primary_key() {
        let seed = mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let primary = derive_primary_only(&seed);
        // Hardcoded known vector — any change to the derivation pipeline breaks this.
        let expected: [u8; 32] = [
            0xb7, 0xdf, 0xe6, 0xb6, 0x75, 0x45, 0xc9, 0xb5, 0x5b, 0xce, 0xba, 0x8f, 0x0f, 0xcb,
            0xa4, 0xd5, 0x15, 0xe7, 0x62, 0x06, 0x22, 0x1a, 0x95, 0x7c, 0x65, 0xeb, 0x75, 0x4e,
            0xc9, 0x43, 0x31, 0x76,
        ];
        assert_eq!(primary, expected);
    }

    #[test]
    fn all_four_keys_are_distinct() {
        let seed = mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let keys = derive_all(&seed);
        let all = [
            keys.primary,
            keys.signing,
            keys.authentication,
            keys.encryption,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "keys {i} and {j} must differ");
            }
        }
    }

    #[test]
    fn determinism() {
        let seed = mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let a = derive_all(&seed);
        let b = derive_all(&seed);
        assert_eq!(a.primary, b.primary);
        assert_eq!(a.signing, b.signing);
        assert_eq!(a.authentication, b.authentication);
        assert_eq!(a.encryption, b.encryption);
    }

    #[test]
    fn different_passphrases_produce_different_seeds() {
        let seed_a = mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let seed_b = mnemonic_to_seed(TEST_MNEMONIC, "test").unwrap();
        assert_ne!(seed_a, seed_b);
    }

    #[test]
    fn valid_mnemonic_parses() {
        assert!(mnemonic_to_seed(TEST_MNEMONIC, "").is_ok());
    }

    #[test]
    fn invalid_mnemonic_fails() {
        assert!(mnemonic_to_seed("not a valid mnemonic phrase at all", "").is_err());
    }
}
