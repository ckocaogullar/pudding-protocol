// Parts of this code are modified code from Arti -- the Tor Rust implementation project
// [Link:] https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/tor-llcrypto/src/pk/keymanip.rs

use thiserror::Error;

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{ExpandedSecretKey, Keypair};
use x25519_dalek::StaticSecret;

use anyhow::Result;

use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use ed25519_dalek::PublicKey as Ed25519PublicKey;

/// A variant of ed25519 [`Keypair`] containing an [`ExpandedSecretKey`].
#[allow(clippy::exhaustive_structs)]
pub struct ExpandedKeypair {
    /// The secret part of the key.
    pub secret: ExpandedSecretKey,
    /// The public part of this key.
    pub public: Ed25519PublicKey,
}

impl<'a> From<&'a Keypair> for ExpandedKeypair {
    fn from(kp: &'a Keypair) -> ExpandedKeypair {
        ExpandedKeypair {
            secret: (&kp.secret).into(),
            public: kp.public,
        }
    }
}

/// An error occurred during a key-blinding operation.
#[derive(Error, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlindingError {
    /// A bad public key was provided for blinding
    #[error("Public key was invalid")]
    BadPubkey,
    /// Dalek failed the scalar multiplication
    #[error("Key blinding failed")]
    BlindingFailed,
}

// Convert this dalek error to a BlindingError
impl From<ed25519_dalek::SignatureError> for BlindingError {
    fn from(_: ed25519_dalek::SignatureError) -> BlindingError {
        BlindingError::BlindingFailed
    }
}

/// Helper: clamp a blinding factor and use it to compute a blinding factor.
///
/// Described in part of rend-spec-v3 A.2.
///
/// This is a common step for public-key and private-key blinding.
pub fn clamp_blinding_factor(mut h: [u8; 32]) -> Scalar {
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;

    // Transform it into a scalar so that we can do scalar mult.
    Scalar::from_bytes_mod_order(h)
}

pub fn convert_x25519_to_ed25519_private(
    private_key: &StaticSecret,
) -> Option<(ExpandedKeypair, u8)> {
    let h = Sha512::new()
        .chain_update(private_key.to_bytes())
        .chain_update(&b"Derive high part of ed25519 key from x25519 key\0"[..])
        .finalize();

    let mut bytes = Zeroizing::new([0_u8; 64]);
    bytes[0..32].clone_from_slice(&private_key.to_bytes());
    bytes[32..64].clone_from_slice(&h[0..32]);

    let secret = ed25519_dalek::ExpandedSecretKey::from_bytes(&bytes[..]).ok()?;
    let public: Ed25519PublicKey = (&secret).into();
    let signbit = public.as_bytes()[31] >> 7;

    Some((ExpandedKeypair { public, secret }, signbit))
}

pub fn blind_pubkey(pk: &Ed25519PublicKey, h: [u8; 32]) -> Result<Ed25519PublicKey> {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let blinding_factor = clamp_blinding_factor(h);

    // Convert the public key to a point on the curve
    let pubkey_point = CompressedEdwardsY(pk.to_bytes())
        .decompress()
        .ok_or(BlindingError::BadPubkey)?;

    // Do the scalar multiplication and get a point back
    let blinded_pubkey_point = (blinding_factor * pubkey_point).compress();
    // Turn the point back into bytes and return it
    Ok(Ed25519PublicKey::from_bytes(&blinded_pubkey_point.0)?)
}

pub fn blind_keypair(keypair: &ExpandedKeypair, h: [u8; 32]) -> Result<ExpandedKeypair> {
    /// Fixed string specified in rend-spec-v3.txt, used for blinding the
    /// original nonce.  (Technically, any string would do, but this one keeps
    /// implementations consistent.)
    const RH_BLIND_STRING: &[u8] = b"Derive temporary signing key hash input";

    let blinding_factor = clamp_blinding_factor(h);
    let secret_key_bytes = Zeroizing::new(keypair.secret.to_bytes());
    let mut blinded_key_bytes = Zeroizing::new([0_u8; 64]);

    {
        let secret_key = Scalar::from_bits(
            secret_key_bytes[0..32]
                .try_into()
                .expect("32-byte array not 32 bytes long!?"),
        );
        let blinded_key = secret_key * blinding_factor;
        blinded_key_bytes[0..32].copy_from_slice(blinded_key.as_bytes());
    }

    {
        let mut h = Sha512::new();
        h.update(RH_BLIND_STRING);
        h.update(&secret_key_bytes[32..]);
        let mut d = Zeroizing::new([0_u8; 64]);
        h.finalize_into(
            d.as_mut()
                .try_into()
                .expect("64-byte array not 64 bytes long!?"),
        );
        blinded_key_bytes[32..64].copy_from_slice(&d[0..32]);
    }

    // We cannot derive our blinded public key from `secret`; we must instead
    // re-blind `public`. (See "Limitations" above for an explanation.)
    let public = blind_pubkey(&keypair.public, h)?;

    let secret = ExpandedSecretKey::from_bytes(&blinded_key_bytes[..])
        .map_err(|_| BlindingError::BlindingFailed)?;
    Ok(ExpandedKeypair { secret, public })
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use ed25519_dalek::{ExpandedSecretKey, Signature, Verifier};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use tracing_test::traced_test;
    use x25519_dalek::PublicKey as X25519PublicKey;

    impl ExpandedKeypair {
        /// Compute a signature over a message using this keypair.
        pub fn sign(&self, message: &[u8]) -> Signature {
            self.secret.sign(message, &self.public)
        }
    }

    /// x25519 keys that are used by Nym should be converted to ed25519 for blinding
    pub fn convert_x25519_to_ed25519_public(
        pubkey: &X25519PublicKey,
        signbit: u8,
    ) -> Option<Ed25519PublicKey> {
        let point = MontgomeryPoint(*pubkey.as_bytes());
        let edpoint = point.to_edwards(signbit)?;

        // TODO: This is inefficient; we shouldn't have to re-compress
        // this point to get the public key we wanted.  But there's no way
        // with the current API that I can to construct an ed25519 public
        // key from a compressed point.
        let compressed_y = edpoint.compress();
        Ed25519PublicKey::from_bytes(compressed_y.as_bytes()).ok()
    }

    #[test]
    #[traced_test]
    fn test_x25519_to_ed25519_compatible() {
        // Create x25519 private key
        let dummy_seed = [42u8; 32];
        let rng = ChaCha20Rng::from_seed(dummy_seed);

        let x25519_seckey = x25519_dalek::StaticSecret::new(rng);

        // Use that to create x25519 public key
        let x25519_pubkey: X25519PublicKey = (&x25519_seckey).into();

        // Now call the convert_x25519_to_ed25519_private function to create a private key
        let (ed_kp, signbit) = convert_x25519_to_ed25519_private(&x25519_seckey).unwrap();
        let ed_seckey = ed_kp.secret;

        // Get the public key value
        // 1) From the converted keypair
        let ed_pubkey1 = ed_kp.public;
        // 2) By generating it directly from the secret key
        let ed_pubkey2: Ed25519PublicKey = (&ed_seckey).into();
        // 3) By converting the x25519 public key using our function
        let ed_pubkey3 = convert_x25519_to_ed25519_public(&x25519_pubkey, signbit).unwrap();

        assert_eq!(ed_pubkey1, ed_pubkey2);
        assert_eq!(ed_pubkey1, ed_pubkey3);

        let msg = b"tis the gift to be simple";
        let sig1 = ed_seckey.sign(&msg[..], &ed_pubkey1);
        assert!(ed_pubkey1.verify(&msg[..], &sig1).is_ok());
        assert!(ed_pubkey2.verify(&msg[..], &sig1).is_ok());
    }

    #[test]
    #[traced_test]
    fn blinding() {
        // Test the ed25519 blinding function.
        //
        // These test vectors are from our ed25519 implementation and related
        // functions. These were automatically generated by the
        // ed25519_exts_ref.py script in little-t-tor and they are also used by
        // little-t-tor and onionbalance:

        let seckeys = [
            b"26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36",
            b"fba7a5366b5cb98c2667a18783f5cf8f4f8d1a2ce939ad22a6e685edde85128d",
            b"67e3aa7a14fac8445d15e45e38a523481a69ae35513c9e4143eb1c2196729a0e",
            b"d51385942033a76dc17f089a59e6a5a7fe80d9c526ae8ddd8c3a506b99d3d0a6",
            b"5c8eac469bb3f1b85bc7cd893f52dc42a9ab66f1b02b5ce6a68e9b175d3bb433",
            b"eda433d483059b6d1ff8b7cfbd0fe406bfb23722c8f3c8252629284573b61b86",
            b"4377c40431c30883c5fbd9bc92ae48d1ed8a47b81d13806beac5351739b5533d",
            b"c6bbcce615839756aed2cc78b1de13884dd3618f48367a17597a16c1cd7a290b",
            b"c6bbcce615839756aed2cc78b1de13884dd3618f48367a17597a16c1cd7a290b",
            b"c6bbcce615839756aed2cc78b1de13884dd3618f48367a17597a16c1cd7a290b",
        ];
        let expanded_seckeys = [b"c0a4de23cc64392d85aa1da82b3defddbea946d13bb053bf8489fa9296281f495022f1f7ec0dcf52f07d4c7965c4eaed121d5d88d0a8ff546b06116a20e97755",
            b"18a8a69a06790dac778e882f7e868baacfa12521a5c058f5194f3a729184514a2a656fe7799c3e41f43d756da8d9cd47a061316cfe6147e23ea2f90d1ca45f30",
            b"58d84f8862d2ecfa30eb491a81c36d05b574310ea69dae18ecb57e992a896656b982187ee96c15bf4caeeab2d0b0ae4cd0b8d17470fc7efa98bb26428f4ef36d",
            b"50702d20b3550c6e16033db5ad4fba16436f1ecc7485be6af62b0732ceb5d173c47ccd9d044b6ea99dd99256adcc9c62191be194e7cb1a5b58ddcec85d876a2b",
            b"7077464c864c2ed5ed21c9916dc3b3ba6256f8b742fec67658d8d233dadc8d5a7a82c371083cc86892c2c8782dda2a09b6baf016aec51b689183ae59ce932ff2",
            b"8883c1387a6c86fc0bd7b9f157b4e4cd83f6885bf55e2706d2235d4527a2f05311a3595953282e436df0349e1bb313a19b3ddbf7a7b91ecce8a2c34abadb38b3",
            b"186791ac8d03a3ac8efed6ac360467edd5a3bed2d02b3be713ddd5be53b3287ee37436e5fd7ac43794394507ad440ecfdf59c4c255f19b768a273109e06d7d8e",
            b"b003077c1e52a62308eef7950b2d532e1d4a7eea50ad22d8ac11b892851f1c40ffb9c9ff8dcd0c6c233f665a2e176324d92416bfcfcd1f787424c0c667452d86",
            b"b003077c1e52a62308eef7950b2d532e1d4a7eea50ad22d8ac11b892851f1c40ffb9c9ff8dcd0c6c233f665a2e176324d92416bfcfcd1f787424c0c667452d86",
            b"b003077c1e52a62308eef7950b2d532e1d4a7eea50ad22d8ac11b892851f1c40ffb9c9ff8dcd0c6c233f665a2e176324d92416bfcfcd1f787424c0c667452d86"];

        let pubkeys = [
            b"c2247870536a192d142d056abefca68d6193158e7c1a59c1654c954eccaff894",
            b"1519a3b15816a1aafab0b213892026ebf5c0dc232c58b21088d88cb90e9b940d",
            b"081faa81992e360ea22c06af1aba096e7a73f1c665bc8b3e4e531c46455fd1dd",
            b"73cfa1189a723aad7966137cbffa35140bb40d7e16eae4c40b79b5f0360dd65a",
            b"66c1a77104d86461b6f98f73acf3cd229c80624495d2d74d6fda1e940080a96b",
            b"d21c294db0e64cb2d8976625786ede1d9754186ae8197a64d72f68c792eecc19",
            b"c4d58b4cf85a348ff3d410dd936fa460c4f18da962c01b1963792b9dcc8a6ea6",
            b"95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
            b"95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
            b"95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
        ];
        let params = [
            "54a513898b471d1d448a2f3c55c1de2c0ef718c447b04497eeb999ed32027823",
            "831e9b5325b5d31b7ae6197e9c7a7baf2ec361e08248bce055908971047a2347",
            "ac78a1d46faf3bfbbdc5af5f053dc6dc9023ed78236bec1760dadfd0b2603760",
            "f9c84dc0ac31571507993df94da1b3d28684a12ad14e67d0a068aba5c53019fc",
            "b1fe79d1dec9bc108df69f6612c72812755751f21ecc5af99663b30be8b9081f",
            "81f1512b63ab5fb5c1711a4ec83d379c420574aedffa8c3368e1c3989a3a0084",
            "97f45142597c473a4b0e9a12d64561133ad9e1155fe5a9807fe6af8a93557818",
            "3f44f6a5a92cde816635dfc12ade70539871078d2ff097278be2a555c9859cd0",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ];
        let blinded_pubkeys = [
            "1fc1fa4465bd9d4956fdbdc9d3acb3c7019bb8d5606b951c2e1dfe0b42eaeb41",
            "1cbbd4a88ce8f165447f159d9f628ada18674158c4f7c5ead44ce8eb0fa6eb7e",
            "c5419ad133ffde7e0ac882055d942f582054132b092de377d587435722deb028",
            "3e08d0dc291066272e313014bfac4d39ad84aa93c038478a58011f431648105f",
            "59381f06acb6bf1389ba305f70874eed3e0f2ab57cdb7bc69ed59a9b8899ff4d",
            "2b946a484344eb1c17c89dd8b04196a84f3b7222c876a07a4cece85f676f87d9",
            "c6b585129b135f8769df2eba987e76e089e80ba3a2a6729134d3b28008ac098e",
            "0eefdc795b59cabbc194c6174e34ba9451e8355108520554ec285acabebb34ac",
            "312404d06a0a9de489904b18d5233e83a50b225977fa8734f2c897a73c067952",
            "952a908a4a9e0e5176a2549f8f328955aca6817a9fdc59e3acec5dec50838108",
        ];
        let blinded_seckeys = ["293c3acff4e902f6f63ddc5d5caa2a57e771db4f24de65d4c28df3232f47fa01171d43f24e3f53e70ec7ac280044ac77d4942dee5d6807118a59bdf3ee647e89",
            "38b88f9f9440358da544504ee152fb475528f7c51c285bd1c68b14ade8e29a07b8ceff20dfcf53eb52b891fc078c934efbf0353af7242e7dc51bb32a093afa29",
            "4d03ce16a3f3249846aac9de0a0075061495c3b027248eeee47da4ddbaf9e0049217f52e92797462bd890fc274672e05c98f2c82970d640084781334aae0f940",
            "51d7db01aaa0d937a9fd7c8c7381445a14d8fa61f43347af5460d7cd8fda9904509ecee77082ce088f7c19d5a00e955eeef8df6fa41686abc1030c2d76807733",
            "1f76cab834e222bd2546efa7e073425680ab88df186ff41327d3e40770129b00b57b95a440570659a440a3e4771465022a8e67af86bdf2d0990c54e7bb87ff9a",
            "c23588c23ee76093419d07b27c6df5922a03ac58f96c53671456a7d1bdbf560ec492fc87d5ec2a1b185ca5a40541fdef0b1e128fd5c2380c888bfa924711bcab",
            "3ed249c6932d076e1a2f6916975914b14e8c739da00992358b8f37d3e790650691b4768f8e556d78f4bdcb9a13b6f6066fe81d3134ae965dc48cd0785b3af2b8",
            "288cbfd923cb286d48c084555b5bdd06c05e92fb81acdb45271367f57515380e053d9c00c81e1331c06ab50087be8cfc7dc11691b132614474f1aa9c2503cccd",
            "e5cd03eb4cc456e11bc36724b558873df0045729b22d8b748360067a7770ac02053d9c00c81e1331c06ab50087be8cfc7dc11691b132614474f1aa9c2503cccd",
            "2cf7ed8b163f5af960d2fc62e1883aa422a6090736b4f18a5456ddcaf78ede0c053d9c00c81e1331c06ab50087be8cfc7dc11691b132614474f1aa9c2503cccd"];

        for i in 0..pubkeys.len() {
            let sk =
                ed25519_dalek::SecretKey::from_bytes(&hex::decode(seckeys[i]).unwrap()).unwrap();
            let esk = ExpandedSecretKey::from(&sk);
            assert_eq!(
                &esk.to_bytes()[..],
                &hex::decode(expanded_seckeys[i]).unwrap()
            );
            let public = (&esk).into();
            let kp_in = ExpandedKeypair {
                secret: esk,
                public,
            };

            let pk = Ed25519PublicKey::from_bytes(&hex::decode(pubkeys[i]).unwrap()).unwrap();
            assert_eq!(pk, Ed25519PublicKey::from(&sk));

            let param = hex::decode(params[i]).unwrap().try_into().unwrap();
            // Blind the secret key, and make sure that the result is expected.
            let blinded_kp = blind_keypair(&kp_in, param).unwrap();
            assert_eq!(
                hex::encode(blinded_kp.secret.to_bytes()),
                blinded_seckeys[i]
            );

            let blinded_pk = blind_pubkey(&pk, param).unwrap();

            // Make sure blinded pk is as expected.
            assert_eq!(hex::encode(blinded_pk.to_bytes()), blinded_pubkeys[i]);

            // Make sure that signature made with blinded sk is validated by
            // blinded pk.
            let sig = blinded_kp.sign(b"hello world");
            blinded_pk.verify(b"hello world", &sig).unwrap();

            if false {
                // This test does not pass: see "limitations" section in documentation for blind_seckey.
                assert_eq!(
                    blinded_pk.to_bytes(),
                    Ed25519PublicKey::from(&blinded_kp.secret).to_bytes()
                );
            } else {
                let blinded_sk_bytes = blinded_kp.secret.to_bytes();
                let blinded_sk_scalar =
                    Scalar::from_bits(blinded_sk_bytes[0..32].try_into().unwrap());
                let pk2 = blinded_sk_scalar * curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
                let pk2 = pk2.compress();
                assert_eq!(pk2.as_bytes(), blinded_pk.as_bytes());
            }
        }
    }
}
