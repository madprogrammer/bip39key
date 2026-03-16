use anyhow::Result;
use sequoia_openpgp as openpgp;
use std::time::{Duration, UNIX_EPOCH};

use openpgp::packet::prelude::*;
use openpgp::packet::{key::Key4, signature::SignatureBuilder, UserID};
use openpgp::serialize::MarshalInto;
use openpgp::types::{KeyFlags, SignatureType, SymmetricAlgorithm};

use crate::derive::DerivedKeyMaterial;

/// Build a full certificate with primary key and signing/encryption/authentication subkeys.
pub fn build_cert(
    keys: &DerivedKeyMaterial,
    userid_str: &str,
    timestamp: u64,
) -> Result<openpgp::cert::Cert> {
    let ts = UNIX_EPOCH + Duration::from_secs(timestamp);

    // Primary key (certification only)
    let primary_key: Key<key::SecretParts, key::PrimaryRole> =
        Key::from(Key4::import_secret_ed25519(&keys.primary, ts)?);
    let primary_pub: Key<key::PublicParts, key::PrimaryRole> =
        primary_key.clone().parts_into_public();
    let mut primary_signer = primary_key.clone().parts_into_secret()?.into_keypair()?;

    // User ID + self-signature
    let userid = UserID::from(userid_str);
    let primary_sig = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_signature_creation_time(ts)?
        .set_key_flags(KeyFlags::empty().set_certification())?
        .set_preferred_symmetric_algorithms(vec![SymmetricAlgorithm::AES256])?
        .sign_userid_binding(&mut primary_signer, None, &userid)?;

    // Signing subkey (Ed25519, requires back-signature)
    let signing_subkey: Key<key::SecretParts, key::SubordinateRole> =
        Key4::<key::SecretParts, key::SubordinateRole>::import_secret_ed25519(
            &keys.signing, ts,
        )?
        .into();
    let mut signing_signer = signing_subkey
        .clone()
        .parts_into_secret()?
        .into_keypair()?;
    let back_sig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
        .set_signature_creation_time(ts)?
        .sign_primary_key_binding(&mut signing_signer, &primary_pub, &signing_subkey)?;
    let signing_binding = SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_signature_creation_time(ts)?
        .set_key_flags(KeyFlags::empty().set_signing())?
        .set_embedded_signature(back_sig)?
        .sign_subkey_binding(&mut primary_signer, &primary_pub, &signing_subkey)?;

    // Encryption subkey (Cv25519 / ECDH)
    let encryption_subkey: Key<key::SecretParts, key::SubordinateRole> =
        Key4::<key::SecretParts, key::SubordinateRole>::import_secret_cv25519(
            &keys.encryption, None, None, ts,
        )?
        .into();
    let encryption_binding = SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_signature_creation_time(ts)?
        .set_key_flags(
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
        )?
        .sign_subkey_binding(&mut primary_signer, &primary_pub, &encryption_subkey)?;

    // Authentication subkey (Ed25519)
    let auth_subkey: Key<key::SecretParts, key::SubordinateRole> =
        Key4::<key::SecretParts, key::SubordinateRole>::import_secret_ed25519(
            &keys.authentication, ts,
        )?
        .into();
    let auth_binding = SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_signature_creation_time(ts)?
        .set_key_flags(KeyFlags::empty().set_authentication())?
        .sign_subkey_binding(&mut primary_signer, &primary_pub, &auth_subkey)?;

    // Assemble packets in order
    let packets: Vec<openpgp::Packet> = vec![
        primary_key.into(),
        userid.into(),
        primary_sig.into(),
        signing_subkey.into(),
        signing_binding.into(),
        encryption_subkey.into(),
        encryption_binding.into(),
        auth_subkey.into(),
        auth_binding.into(),
    ];

    Ok(openpgp::cert::Cert::from_packets(packets.into_iter())?)
}

/// Build a minimal certificate with primary key only (no subkeys).
pub fn build_cert_primary_only(
    primary_material: &[u8; 32],
    userid_str: &str,
    timestamp: u64,
) -> Result<openpgp::cert::Cert> {
    let ts = UNIX_EPOCH + Duration::from_secs(timestamp);

    let primary_key: Key<key::SecretParts, key::PrimaryRole> =
        Key::from(Key4::import_secret_ed25519(primary_material, ts)?);
    let mut signer = primary_key.clone().parts_into_secret()?.into_keypair()?;

    let userid = UserID::from(userid_str);
    let sig = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_signature_creation_time(ts)?
        .set_key_flags(KeyFlags::empty().set_certification())?
        .set_preferred_symmetric_algorithms(vec![SymmetricAlgorithm::AES256])?
        .sign_userid_binding(&mut signer, None, &userid)?;

    let packets: Vec<openpgp::Packet> = vec![primary_key.into(), userid.into(), sig.into()];

    Ok(openpgp::cert::Cert::from_packets(packets.into_iter())?)
}

/// Serialize a certificate to armored TSK (Transferable Secret Key) format.
pub fn cert_to_armored(cert: &openpgp::cert::Cert) -> Result<String> {
    Ok(String::from_utf8(cert.as_tsk().armored().to_vec()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive;
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_USERID: &str = "Test User <test@example.com>";
    const TEST_TIMESTAMP: u64 = 1231006505;

    fn test_seed() -> [u8; 64] {
        derive::mnemonic_to_seed(TEST_MNEMONIC, "").unwrap()
    }

    #[test]
    fn primary_only_cert_structure() {
        let seed = test_seed();
        let primary = derive::derive_primary_only(&seed);
        let cert =
            build_cert_primary_only(&primary, TEST_USERID, TEST_TIMESTAMP).unwrap();
        let policy = &StandardPolicy::new();
        let valid = cert.with_policy(policy, None).unwrap();
        assert_eq!(valid.keys().count(), 1);
        assert_eq!(
            valid.userids().next().unwrap().userid().value(),
            TEST_USERID.as_bytes()
        );
    }

    #[test]
    fn full_cert_structure() {
        let seed = test_seed();
        let keys = derive::derive_all(&seed);
        let cert = build_cert(&keys, TEST_USERID, TEST_TIMESTAMP).unwrap();
        let policy = &StandardPolicy::new();
        let valid = cert.with_policy(policy, None).unwrap();
        // 1 primary + 3 subkeys = 4 keys total
        assert_eq!(valid.keys().count(), 4);
    }

    #[test]
    fn full_cert_key_flags() {
        let seed = test_seed();
        let keys = derive::derive_all(&seed);
        let cert = build_cert(&keys, TEST_USERID, TEST_TIMESTAMP).unwrap();
        let policy = &StandardPolicy::new();
        let valid = cert.with_policy(policy, None).unwrap();

        let primary = valid.primary_key();
        let primary_flags = primary.key_flags().unwrap();
        assert!(primary_flags.for_certification());
        assert!(!primary_flags.for_signing());

        let subkeys: Vec<_> = valid.keys().subkeys().collect();
        assert_eq!(subkeys.len(), 3);

        let has_signing = subkeys
            .iter()
            .any(|k| k.key_flags().map_or(false, |f| f.for_signing()));
        let has_encryption = subkeys.iter().any(|k| {
            k.key_flags()
                .map_or(false, |f| f.for_transport_encryption())
        });
        let has_auth = subkeys
            .iter()
            .any(|k| k.key_flags().map_or(false, |f| f.for_authentication()));

        assert!(has_signing, "must have a signing subkey");
        assert!(has_encryption, "must have an encryption subkey");
        assert!(has_auth, "must have an authentication subkey");
    }

    #[test]
    fn full_cert_passes_policy_validation() {
        let seed = test_seed();
        let keys = derive::derive_all(&seed);
        let cert = build_cert(&keys, TEST_USERID, TEST_TIMESTAMP).unwrap();
        let policy = &StandardPolicy::new();
        // This catches missing back-signatures and other structural issues.
        assert!(cert.with_policy(policy, None).is_ok());
    }

    #[test]
    fn deterministic_key_material() {
        // Key material is deterministic, but signatures contain random salt
        // (sequoia-openpgp adds salt@notations for security). So we compare
        // fingerprints and key data, not the full armored output.
        let seed = test_seed();
        let keys = derive::derive_all(&seed);
        let a = build_cert(&keys, TEST_USERID, TEST_TIMESTAMP).unwrap();
        let b = build_cert(&keys, TEST_USERID, TEST_TIMESTAMP).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        let a_keys: Vec<_> = a.keys().map(|k| k.fingerprint()).collect();
        let b_keys: Vec<_> = b.keys().map(|k| k.fingerprint()).collect();
        assert_eq!(a_keys, b_keys);
    }

    #[test]
    fn primary_fingerprint_matches_between_full_and_primary_only() {
        let seed = test_seed();
        let keys = derive::derive_all(&seed);
        let full = build_cert(&keys, TEST_USERID, TEST_TIMESTAMP).unwrap();
        let primary_only =
            build_cert_primary_only(&keys.primary, TEST_USERID, TEST_TIMESTAMP).unwrap();
        assert_eq!(full.fingerprint(), primary_only.fingerprint());
    }

    #[test]
    fn different_timestamps_produce_different_keys() {
        let seed = test_seed();
        let keys = derive::derive_all(&seed);
        let a = build_cert(&keys, TEST_USERID, 0).unwrap();
        let b = build_cert(&keys, TEST_USERID, 1_000_000).unwrap();
        // Different timestamps produce different fingerprints
        // because the creation time is part of the key packet.
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn armored_output_round_trips() {
        let seed = test_seed();
        let keys = derive::derive_all(&seed);
        let cert = build_cert(&keys, TEST_USERID, TEST_TIMESTAMP).unwrap();
        let armored = cert_to_armored(&cert).unwrap();
        let parsed = openpgp::cert::Cert::from_bytes(armored.as_bytes()).unwrap();
        assert_eq!(cert.fingerprint(), parsed.fingerprint());
    }
}
