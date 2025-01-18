use ic_cose::rand_bytes;
use ic_cose_types::{
    cose::kdf::derive_a256gcm_key,
    cose::{
        ecdh::ecdh_x25519,
        encrypt0::{cose_decrypt0, cose_encrypt0},
        mac3_256,
    },
    types::{ECDHInput, ECDHOutput},
    BoxError,
};
use serde_bytes::{ByteArray, ByteBuf};

/// Derives a 256-bit AES-GCM key from a root secret and derivation path.
///
/// The derivation path is hashed using HMAC-SHA256 with "A256GCM" as the context string
/// to create a salt. The root secret is then used with HKDF to derive the final key.
pub fn a256gcm_key(root_secret: &[u8], derivation_path: Vec<Vec<u8>>) -> ByteArray<32> {
    let salt: Vec<u8> = derivation_path
        .into_iter()
        .flat_map(|slice| slice.into_iter())
        .collect();
    let salt = mac3_256(&salt, b"A256GCM");
    let key = derive_a256gcm_key(root_secret, Some(&salt));
    key.into()
}

/// Derives an AES-GCM-256 key using ECDH (Elliptic Curve Diffie-Hellman) key exchange.
///
/// Combines a root secret with a derivation path to create a base key, then performs:
/// 1. X25519 key exchange to generate a shared secret
/// 2. Encrypts the derived key using COSE_Encrypt0 with the shared secret
///
/// Returns the encrypted key and the ephemeral public key used in the exchange.
pub fn a256gcm_ecdh_key(
    root_secret: &[u8],
    derivation_path: Vec<Vec<u8>>,
    ecdh: &ECDHInput,
) -> ECDHOutput<ByteBuf> {
    let salt: Vec<u8> = derivation_path
        .into_iter()
        .flat_map(|slice| slice.into_iter())
        .collect();
    let salt = mac3_256(&salt, b"A256GCM_ECDH");
    let key = derive_a256gcm_key(root_secret, Some(&salt));
    let secret_key: [u8; 32] = rand_bytes();
    let secret_key = mac3_256(&secret_key, ecdh.nonce.as_ref());
    let (shared_secret, public_key) = ecdh_x25519(secret_key, *ecdh.public_key);
    let key = cose_encrypt0(&key, shared_secret.as_bytes(), &[], &ecdh.nonce, None)
        .expect("a256gcm_key: failed to encrypt key");
    ECDHOutput {
        payload: key.into(),
        public_key: public_key.to_bytes().into(),
    }
}

/// Decrypts a COSE_Encrypt0 payload using ECDH (Elliptic Curve Diffie-Hellman).
///
/// Takes a secret key and ECDH output containing:
/// - Encrypted payload
/// - Ephemeral public key
///
/// Performs X25519 key exchange to derive shared secret, then uses it to decrypt
/// the payload with AES-GCM-256.
///
/// Returns the decrypted payload or an error if decryption fails.
pub fn decrypt_ecdh(secret_key: [u8; 32], ecdh: &ECDHOutput<ByteBuf>) -> Result<ByteBuf, BoxError> {
    let (shared_secret, _) = ecdh_x25519(secret_key, *ecdh.public_key);
    let key = cose_decrypt0(&ecdh.payload, shared_secret.as_bytes(), &[])?;
    Ok(key.into())
}

/// Signs a message using Ed25519 signature scheme.
///
/// Derives a signing key from:
/// - Root secret (seed)
/// - Derivation path (for hierarchical key derivation)
///
/// Returns a 64-byte signature that can be verified with the corresponding public key.
pub fn ed25519_sign_message(
    root_secret: &[u8],
    derivation_path: Vec<Vec<u8>>,
    msg: &[u8],
) -> ByteArray<64> {
    let sk = ic_crypto_ed25519::PrivateKey::generate_from_seed(root_secret);
    let path = ic_crypto_ed25519::DerivationPath::new(
        derivation_path
            .into_iter()
            .map(ic_crypto_ed25519::DerivationIndex)
            .collect(),
    );
    let (sk, _) = sk.derive_subkey(&path);
    let sig = sk.sign_message(msg);
    sig.into()
}

/// Derives an Ed25519 public key and chain code from a root secret and derivation path.
///
/// # Arguments
/// * `root_secret` - Seed for key generation (48 bytes)
/// * `derivation_path` - Hierarchical path for key derivation
///
/// # Returns
/// Tuple containing:
/// * Public key (32 bytes)
/// * Chain code (32 bytes) for further derivation
pub fn ed25519_public_key(
    root_secret: &[u8],
    derivation_path: Vec<Vec<u8>>,
) -> (ByteArray<32>, ByteArray<32>) {
    let sk = ic_crypto_ed25519::PrivateKey::generate_from_seed(root_secret);
    let path = ic_crypto_ed25519::DerivationPath::new(
        derivation_path
            .into_iter()
            .map(ic_crypto_ed25519::DerivationIndex)
            .collect(),
    );
    let pk = sk.public_key();
    let (pk, chain_code) = pk.derive_subkey(&path);
    (pk.serialize_raw().into(), chain_code.into())
}

/// Derives a new Ed25519 public key and chain code from an existing public key.
///
/// # Arguments
/// * `public_key` - Base public key (32 bytes)
/// * `chain_code` - Chain code from previous derivation (32 bytes)
/// * `derivation_path` - Hierarchical path for key derivation
///
/// # Returns
/// Tuple containing:
/// * Derived public key (32 bytes)
/// * New chain code (32 bytes) for further derivation
pub fn derive_ed25519_public_key(
    public_key: &[u8; 32],
    chain_code: &[u8; 32],
    derivation_path: Vec<Vec<u8>>,
) -> (ByteArray<32>, ByteArray<32>) {
    let path = ic_crypto_ed25519::DerivationPath::new(
        derivation_path
            .into_iter()
            .map(ic_crypto_ed25519::DerivationIndex)
            .collect(),
    );

    let pk = ic_crypto_ed25519::PublicKey::deserialize_raw(public_key).expect("invalid public key");
    let (pk, chain_code) = pk.derive_subkey_with_chain_code(&path, chain_code);
    (pk.serialize_raw().into(), chain_code.into())
}

/// Signs a message using BIP-340 Schnorr signature scheme for secp256k1.
///
/// Derives a signing key from:
/// - Root secret (seed)
/// - Derivation path (for hierarchical key derivation)
///
/// Returns a 64-byte Schnorr signature that can be verified with the corresponding public key.
pub fn secp256k1_sign_message_bip340(
    root_secret: &[u8],
    derivation_path: Vec<Vec<u8>>,
    msg: &[u8],
) -> ByteArray<64> {
    let sk = ic_crypto_secp256k1::PrivateKey::generate_from_seed(root_secret);
    let path = ic_crypto_secp256k1::DerivationPath::new(
        derivation_path
            .into_iter()
            .map(ic_crypto_secp256k1::DerivationIndex)
            .collect(),
    );
    let (sk, _) = sk.derive_subkey(&path);
    let sig = sk.sign_message_with_bip340_no_rng(msg);
    sig.into()
}

/// Signs a message using ECDSA (Elliptic Curve Digital Signature Algorithm) for secp256k1.
///
/// Derives a signing key from:
/// - Root secret (seed)
/// - Derivation path (for hierarchical key derivation)
///
/// Returns a 64-byte ECDSA signature that can be verified with the corresponding public key.
pub fn secp256k1_sign_message_ecdsa(
    root_secret: &[u8],
    derivation_path: Vec<Vec<u8>>,
    msg: &[u8],
) -> ByteArray<64> {
    let sk = ic_crypto_secp256k1::PrivateKey::generate_from_seed(root_secret);
    let path = ic_crypto_secp256k1::DerivationPath::new(
        derivation_path
            .into_iter()
            .map(ic_crypto_secp256k1::DerivationIndex)
            .collect(),
    );
    let (sk, _) = sk.derive_subkey(&path);
    let sig = sk.sign_message_with_ecdsa(msg);
    sig.into()
}

/// Derives a secp256k1 public key and chain code from a root secret and derivation path.
///
/// # Arguments
/// * `root_secret` - Seed for key generation
/// * `derivation_path` - Hierarchical path for key derivation
///
/// # Returns
/// Tuple containing:
/// * Compressed SEC1-encoded public key (33 bytes)
/// * Chain code (32 bytes) for further derivation
pub fn secp256k1_public_key(
    root_secret: &[u8],
    derivation_path: Vec<Vec<u8>>,
) -> (ByteArray<33>, ByteArray<32>) {
    let sk = ic_crypto_secp256k1::PrivateKey::generate_from_seed(root_secret);
    let path = ic_crypto_secp256k1::DerivationPath::new(
        derivation_path
            .into_iter()
            .map(ic_crypto_secp256k1::DerivationIndex)
            .collect(),
    );
    let pk = sk.public_key();
    let (pk, chain_code) = pk.derive_subkey(&path);
    let pk = pk.serialize_sec1(true);
    let pk: [u8; 33] = pk
        .try_into()
        .expect("secp256k1_public_key: invalid SEC1 public key");
    (pk.into(), chain_code.into())
}

/// Derives a new secp256k1 public key from an existing one using chain code and derivation path.
///
/// # Arguments
/// * `public_key` - Base compressed SEC1-encoded public key (33 bytes)
/// * `chain_code` - Chain code from previous derivation (32 bytes)
/// * `derivation_path` - Hierarchical path for key derivation
///
/// # Returns
/// Result containing:
/// * Derived compressed SEC1-encoded public key (33 bytes)
/// * New chain code (32 bytes) for further derivation
///   or an error if public key deserialization fails
pub fn derive_secp256k1_public_key(
    public_key: &[u8; 33],
    chain_code: &[u8; 32],
    derivation_path: Vec<Vec<u8>>,
) -> Result<(ByteArray<33>, ByteArray<32>), BoxError> {
    let path = ic_crypto_secp256k1::DerivationPath::new(
        derivation_path
            .into_iter()
            .map(ic_crypto_secp256k1::DerivationIndex)
            .collect(),
    );

    let pk = ic_crypto_secp256k1::PublicKey::deserialize_sec1(public_key)?;
    let (pk, chain_code) = pk.derive_subkey_with_chain_code(&path, chain_code);
    let pk = pk.serialize_sec1(true);
    let pk: [u8; 33] = pk
        .try_into()
        .expect("secp256k1_public_key: invalid SEC1 public key");
    Ok((pk.into(), chain_code.into()))
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_cose_types::cose::k256::{secp256k1_verify_bip340, secp256k1_verify_ecdsa};
    use ic_cose_types::cose::{ecdh, ed25519::ed25519_verify, sha256};

    const ROOT_SECRET: [u8; 48] = [0u8; 48];

    #[test]
    fn ed25519_works() {
        let msg = b"hello";
        let sig = ed25519_sign_message(&ROOT_SECRET, vec![], msg);
        let (pk, code) = ed25519_public_key(&ROOT_SECRET, vec![]);
        assert!(ed25519_verify(&pk, msg, sig.as_slice()).is_ok());

        let sig = ed25519_sign_message(&ROOT_SECRET, vec![b"v1".to_vec()], msg);
        let (pk, code) = derive_ed25519_public_key(&pk, &code, vec![b"v1".to_vec()]);
        assert!(ed25519_verify(&pk, msg, sig.as_slice()).is_ok());

        let sig = ed25519_sign_message(&ROOT_SECRET, vec![b"v1".to_vec(), b"test".to_vec()], msg);
        let (pk, _) = derive_ed25519_public_key(&pk, &code, vec![b"test".to_vec()]);
        assert!(ed25519_verify(&pk, msg, sig.as_slice()).is_ok());
    }

    #[test]
    fn secp256k1_bip340_works() {
        let msg = b"hello";
        let sig = secp256k1_sign_message_bip340(&ROOT_SECRET, vec![], msg);
        let (pk, code) = secp256k1_public_key(&ROOT_SECRET, vec![]);
        assert!(secp256k1_verify_bip340(pk.as_slice(), msg, sig.as_slice()).is_ok());

        let sig = secp256k1_sign_message_bip340(&ROOT_SECRET, vec![b"v1".to_vec()], msg);
        let (pk, code) = derive_secp256k1_public_key(&pk, &code, vec![b"v1".to_vec()]).unwrap();
        assert!(secp256k1_verify_bip340(pk.as_slice(), msg, sig.as_slice()).is_ok());

        let sig = secp256k1_sign_message_bip340(
            &ROOT_SECRET,
            vec![b"v1".to_vec(), b"test".to_vec()],
            msg,
        );
        let (pk, _) = derive_secp256k1_public_key(&pk, &code, vec![b"test".to_vec()]).unwrap();
        assert!(secp256k1_verify_bip340(pk.as_slice(), msg, sig.as_slice()).is_ok());
    }

    #[test]
    fn secp256k1_ecdsa_works() {
        let msg = b"hello";
        let sig = secp256k1_sign_message_ecdsa(&ROOT_SECRET, vec![], msg);
        let (pk, code) = secp256k1_public_key(&ROOT_SECRET, vec![]);
        assert!(
            secp256k1_verify_ecdsa(pk.as_slice(), sha256(msg).as_slice(), sig.as_slice()).is_ok()
        );

        let sig = secp256k1_sign_message_ecdsa(&ROOT_SECRET, vec![b"v1".to_vec()], msg);
        let (pk, code) = derive_secp256k1_public_key(&pk, &code, vec![b"v1".to_vec()]).unwrap();
        assert!(
            secp256k1_verify_ecdsa(pk.as_slice(), sha256(msg).as_slice(), sig.as_slice()).is_ok()
        );

        let sig =
            secp256k1_sign_message_ecdsa(&ROOT_SECRET, vec![b"v1".to_vec(), b"test".to_vec()], msg);
        let (pk, _) = derive_secp256k1_public_key(&pk, &code, vec![b"test".to_vec()]).unwrap();
        assert!(
            secp256k1_verify_ecdsa(pk.as_slice(), sha256(msg).as_slice(), sig.as_slice()).is_ok()
        );
    }

    #[test]
    fn a256gcm_key_works() {
        let nonce: [u8; 12] = rand_bytes();
        let secret_key: [u8; 32] = rand_bytes();
        let secret = ecdh::StaticSecret::from(secret_key);
        let public = ecdh::PublicKey::from(&secret);
        let output = a256gcm_ecdh_key(
            &ROOT_SECRET,
            vec![],
            &ECDHInput {
                public_key: public.to_bytes().into(),
                nonce: nonce.into(),
            },
        );
        let key = decrypt_ecdh(secret_key, &output).unwrap();
        assert_eq!(key.len(), 32);

        let nonce: [u8; 12] = rand_bytes();
        let secret_key: [u8; 32] = rand_bytes();
        let secret = ecdh::StaticSecret::from(secret_key);
        let public = ecdh::PublicKey::from(&secret);
        let output = a256gcm_ecdh_key(
            &ROOT_SECRET,
            vec![],
            &ECDHInput {
                public_key: public.to_bytes().into(),
                nonce: nonce.into(),
            },
        );
        let key2 = decrypt_ecdh(secret_key, &output).unwrap();
        assert_eq!(key, key2);

        let key3 = a256gcm_key(&ROOT_SECRET, vec![]);
        assert_ne!(key.as_slice(), key3.as_slice());
    }
}
