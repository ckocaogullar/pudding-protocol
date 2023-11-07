use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key};
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use getrandom::getrandom;
use hex::encode;
use num_bigint::BigUint;
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

#[allow(unused)] // it's actually used
use rand_chacha::ChaCha20Rng;

#[allow(unused)] // it's actually used
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::random(&mut OsRng);
    let verify_key = VerifyingKey::from(&signing_key);
    (signing_key, verify_key)
}

pub fn sign(signing_key: &SigningKey, message: &String) -> String {
    let signature_bytes: Signature = signing_key.sign(message.as_bytes());
    let signature_vec: Vec<u8> = signature_bytes.to_vec();
    let signature_string: String = encode(signature_vec);
    signature_string
}

pub fn verify(verifying_key: &VerifyingKey, message: &String, signature_string: &String) -> bool {
    let _message_bytes = message.as_bytes();
    let signature_bytes = hex::decode(signature_string).unwrap();
    let signature = Signature::from_slice(&signature_bytes).unwrap();
    verifying_key.verify(message.as_bytes(), &signature).is_ok()
}

pub fn random_bigint() -> BigUint {
    let mut random_bytes = vec![0u8; 32];
    getrandom(&mut random_bytes).expect("Failed to generate random bytes");
    BigUint::from_bytes_be(&random_bytes)
}

// For generating a pseudorandom y value using KDF(nonce || id || k) as a seed (see LOOKUP)
pub fn generate_blinding_factor_y(seed: &[u8; 64]) -> [u8; 32] {
    // Create a new SHA-512 hasher
    let mut hasher = Sha256::new();

    // Hash the seed
    hasher.update(seed);

    // Obtain the hash result (output) as a fixed-size array
    let hash_output = hasher.finalize();

    // Convert the generic array to a regular array of 32 bytes
    let result: [u8; 32] = hash_output.into();

    // Return the result
    result
}

//
// Concatenate values to generate messages to be signed, as defined by the protocol
//

// From LOOKUP: sig_A = Sign_sk(message_a), where message_a = nonce ∥ surbs ∥ bpk.
pub fn generate_message_a(nonce: BigUint, surbs: Vec<String>, bpk: &Ed25519PublicKey) -> String {
    let byte_bpk = bpk.to_bytes();
    let bpk_encoded = encode(byte_bpk);

    // Join the elements of the surbs vector with an empty separator (concatenate them)
    let surb_concatenated = surbs.join("");

    nonce.to_string() + &surb_concatenated + &bpk_encoded
}

// From LOOKUP: sig_B = Sign_sk(nonce ∥ y)
pub fn generate_message_b(nonce: BigUint, y: [u8; 32]) -> String {
    // Convert nonce to a string
    let nonce_string = nonce.to_string();

    // Convert y to a hexadecimal string
    let y_hex_string: String = y.iter().map(|b| format!("{:02x}", b)).collect();

    nonce_string + &y_hex_string
}

pub fn aes_encrypt(key: &[u8; 32], message: Vec<u8>) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(key);

    // can be constant because we don't reuse keys (?)
    let nonce = aes_gcm::Nonce::from_slice(&[0; 96 / 8]);

    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, message.as_ref());
    ciphertext.unwrap()
}

pub fn aes_decrypt(key: &[u8; 32], ciphertet: Vec<u8>) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(key);

    // can be constant because we don't reuse keys (?)
    let nonce = aes_gcm::Nonce::from_slice(&[0; 96 / 8]);

    let cipher = Aes256Gcm::new(key);
    let message = cipher.decrypt(nonce, ciphertet.as_ref());
    message.unwrap()
}

#[derive(Clone, Copy)]
pub struct PuddingX25519PrivateKey(pub Scalar);

// TODO: This is a ad-hoc solution that works but probably comes with some subtle breaks as we
// removed some intermediate clamps
impl PuddingX25519PrivateKey {
    #[cfg(test)]
    pub fn new<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        PuddingX25519PrivateKey(clamp(bytes))
    }

    pub fn from(sk: x25519_dalek::StaticSecret) -> Self {
        PuddingX25519PrivateKey(clamp(sk.to_bytes()))
    }

    pub fn derive_public_key(&self) -> PuddingX25519PublicKey {
        PuddingX25519PublicKey(X25519_BASEPOINT * self.0)
    }

    pub fn blind(&self, h: [u8; 32]) -> PuddingX25519PrivateKey {
        let blinding_factor = clamp(h);
        let blinded_sk = self.0 * blinding_factor;
        PuddingX25519PrivateKey(blinded_sk)
    }

    pub fn dh(&self, their_pk: &PuddingX25519PublicKey) -> [u8; 32] {
        let r = self.0 * their_pk.0;
        r.to_bytes()
    }
}

#[derive(Clone, Copy, Eq)]
pub struct PuddingX25519PublicKey(pub MontgomeryPoint);

impl PartialEq for PuddingX25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl PuddingX25519PublicKey {
    pub fn blind(&self, h: [u8; 32]) -> PuddingX25519PublicKey {
        let blinding_factor = clamp(h);
        let blinded_pk = self.0 * blinding_factor;
        PuddingX25519PublicKey(blinded_pk)
    }

    pub fn from(bytes: [u8; 32]) -> Self {
        let point = MontgomeryPoint(bytes);
        PuddingX25519PublicKey(point)
    }
}

fn clamp(mut scalar: [u8; 32]) -> Scalar {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    Scalar::from_bits(scalar)
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::X25519_BASEPOINT;
    use rand_chacha::rand_core::SeedableRng;
    use tracing::debug;
    use tracing_test::traced_test;

    #[allow(unused)]
    use x25519_dalek::PublicKey as X25519PublicKey;

    use super::*;

    #[test]
    #[traced_test]
    fn test_sign_and_verify() {
        // Generate random signing and verifying keys for testing
        let (signing_key, verify_key) = generate_keypair();

        let message = "This is a test message".to_string();

        // Sign the message
        let signature = sign(&signing_key, &message);

        // Verify the signature
        let verification_result = verify(&verify_key, &message, &signature);
        debug!("Verification result {}", verification_result);

        // Assert that the verification is successful
        assert!(verification_result);
    }

    #[test]
    fn test_signature_serialization() {
        // Create a test signature
        let signature_bytes = vec![0x01, 0x02, 0x03, 0x04];
        let signature_string = encode(signature_bytes);

        // Assert that the serialized signature matches the expected value
        assert_eq!(signature_string, "01020304");
    }

    #[test]
    fn test_aes() {
        let message = Vec::from("My secret message");
        let key = [42u8; 32];

        let ciphertext = aes_encrypt(&key, message.clone());

        let recovered = aes_decrypt(&key, ciphertext);
        assert_eq!(message, recovered);
    }

    #[test]
    fn test_puddingx25519publickey_from_bytes() {
        let dummy_seed = [58u8; 32];
        let rng = ChaCha20Rng::from_seed(dummy_seed);

        let alice_secret = x25519_dalek::StaticSecret::new(rng);
        let alice_public = X25519PublicKey::from(&alice_secret);

        let alice_pudding_pk = PuddingX25519PublicKey::from(*alice_public.as_bytes());
        let alice_pudding_sk = PuddingX25519PrivateKey::from(alice_secret);

        let bob_sk = PuddingX25519PrivateKey::new(OsRng);
        let bob_pk = bob_sk.derive_public_key();

        {
            let shared_secret_ab = alice_pudding_sk.dh(&bob_pk);
            let shared_secret_ba = bob_sk.dh(&alice_pudding_pk);
            assert_eq!(shared_secret_ab, shared_secret_ba)
        }
    }

    #[test]
    fn scalar_experiments() {
        let x = Scalar::from_bits([
            0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84, 0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2,
            0x7d, 0x52, 0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44, 0xd4, 0x49, 0xf4, 0xa8,
            0x79, 0xd9, 0xf2, 0x04,
        ]);
        let y = Scalar::from_bits([
            0x90, 0x76, 0x33, 0xfe, 0x1c, 0x4b, 0x66, 0xa4, 0xa2, 0x8d, 0x2d, 0xd7, 0x67, 0x83,
            0x86, 0xc3, 0x53, 0xd0, 0xde, 0x54, 0x55, 0xd4, 0xfc, 0x9d, 0xe8, 0xef, 0x7a, 0xc3,
            0x1f, 0x35, 0xbb, 0x05,
        ]);
        let test_scalar = x * Scalar::one();
        assert_eq!(test_scalar.to_bytes(), x.to_bytes());

        let x = x.reduce();

        // g ^ x
        let pk = X25519_BASEPOINT * x;

        // x * y
        let blinded_priv_key = x * y;

        // (g ^ x) ^ y
        let blinded_pub_key = pk * y;

        // g ^ (x * y)
        let pub_key_of_blinded_priv_key = X25519_BASEPOINT * blinded_priv_key;

        assert_eq!(
            blinded_pub_key.to_bytes(),
            pub_key_of_blinded_priv_key.to_bytes()
        );
    }

    #[test]
    fn blind_x25519() {
        let alice_sk = PuddingX25519PrivateKey::new(OsRng);
        let alice_pk = alice_sk.derive_public_key();

        let bob_sk = PuddingX25519PrivateKey::new(OsRng);
        let bob_pk = bob_sk.derive_public_key();

        // Test normal; without blinding
        {
            let shared_secret_ab = alice_sk.dh(&bob_pk);
            let shared_secret_ba = bob_sk.dh(&alice_pk);
            assert_eq!(shared_secret_ab, shared_secret_ba)
        }

        // Test that we can re-derive the public key
        {
            let h = [42u8; 32];
            let x = PuddingX25519PrivateKey::new(OsRng);
            // x
            eprintln!("x={:?}", x.0.to_bytes());

            // g ^ x
            let pub_x = x.derive_public_key();

            // x * h
            let blinded_x = x.blind(h);

            // g ^ (x * h)
            let pub_from_blinded_x = blinded_x.derive_public_key();

            // (g ^ x) ^ h
            let original_pub_x_blinded = pub_x.blind(h);

            // g ^ (x * h) == (g ^ x) ^ h
            assert_eq!(
                pub_from_blinded_x.0.to_bytes(),
                original_pub_x_blinded.0.to_bytes()
            );
        }

        // Test DH with blinding
        {
            // Blind Alice
            let h = [42u8; 32];
            let alice_sk = alice_sk.blind(h);
            let alice_pk = alice_pk.blind(h);

            // Blind Bob
            let i = [41u8; 32];
            let bob_sk = bob_sk.blind(i);
            let bob_pk = bob_pk.blind(i);

            // Then DH and compare
            let shared_secret_ab = alice_sk.dh(&bob_pk);
            let shared_secret_ba = bob_sk.dh(&alice_pk);
            assert_eq!(shared_secret_ab, shared_secret_ba)
        }
    }
}
