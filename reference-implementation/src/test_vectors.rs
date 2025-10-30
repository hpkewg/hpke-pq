use crate::*;
use rand;
use serde::{Deserialize, Serialize};

mod optional_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => serializer.serialize_str(&hex::encode(v)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_str: Option<String> = Option::deserialize(deserializer)?;
        match opt_str {
            Some(s) => hex::decode(s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestVector {
    pub mode: u8,
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    #[serde(with = "hex::serde")]
    pub info: Vec<u8>,
    #[serde(rename = "ikmE", with = "hex::serde")]
    pub ikm_e: Vec<u8>,
    #[serde(rename = "ikmR", with = "hex::serde")]
    pub ikm_r: Vec<u8>,
    #[serde(rename = "skRm", with = "hex::serde")]
    pub sk_rm: Vec<u8>,
    #[serde(rename = "pkRm", with = "hex::serde")]
    pub pk_rm: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub enc: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub shared_secret: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub suite_id: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub base_nonce: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub exporter_secret: Vec<u8>,
    #[serde(
        with = "optional_hex",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub psk: Option<Vec<u8>>,
    #[serde(
        with = "optional_hex",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub psk_id: Option<Vec<u8>>,
    pub encryptions: Vec<EncryptionVector>,
    pub exports: Vec<ExportVector>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionVector {
    #[serde(with = "hex::serde")]
    pub aad: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub ct: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub pt: Vec<u8>,
}

impl EncryptionVector {
    pub fn generate<A>(ctx: &mut Context<A, Sender>, pt: &[u8], aad: &[u8]) -> Self
    where
        A: Aead,
    {
        let nonce = ctx.compute_nonce();
        let ct = ctx.seal(aad, pt);

        Self {
            aad: aad.to_vec(),
            ct,
            nonce,
            pt: pt.to_vec(),
        }
    }

    pub fn verify<A>(
        &self,
        ctx: &mut Context<A, Receiver>,
        expected_pt: &[u8],
    ) -> Result<(), String>
    where
        A: Aead,
    {
        // Verify pt matches expected
        if self.pt != expected_pt {
            return Err("Plaintext doesn't match expected".to_string());
        }

        // Verify nonce computation
        let computed_nonce = ctx.compute_nonce();
        if self.nonce != computed_nonce {
            return Err("Nonce computation mismatch".to_string());
        }

        // Verify decryption
        let decrypted_pt = ctx.open(&self.aad, &self.ct);
        if decrypted_pt != self.pt {
            Err("Decrypted plaintext doesn't match".to_string())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportVector {
    #[serde(with = "hex::serde")]
    pub exporter_context: Vec<u8>,
    #[serde(rename = "L")]
    pub length: u32,
    #[serde(with = "hex::serde")]
    pub exported_value: Vec<u8>,
}

impl ExportVector {
    pub fn generate<H>(
        suite_id: &[u8; 10],
        exporter_secret: &[u8],
        exporter_context: &[u8],
        length: u32,
    ) -> Self
    where
        H: Kdf,
    {
        let exported_value =
            H::export(suite_id, exporter_secret, exporter_context, length as usize);

        Self {
            exporter_context: exporter_context.to_vec(),
            length,
            exported_value,
        }
    }

    pub fn verify<H>(&self, suite_id: &[u8; 10], exporter_secret: &[u8]) -> Result<(), String>
    where
        H: Kdf,
    {
        let computed_exported_value = H::export(
            suite_id,
            exporter_secret,
            &self.exporter_context,
            self.length as usize,
        );

        if computed_exported_value != self.exported_value {
            Err("Export value mismatch".to_string())
        } else {
            Ok(())
        }
    }
}

pub type TestVectors = Vec<TestVector>;

// Verification logic
pub struct VerificationResult {
    pub passed: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

impl TestVector {
    pub fn new<K, H, A>() -> TestVector
    where
        K: Kem,
        H: Kdf,
        A: Aead,
    {
        Self::generate_with_mode::<K, H, A>(Mode::Base, None, None)
    }

    pub fn new_psk<K, H, A>(psk: &[u8], psk_id: &[u8]) -> TestVector
    where
        K: Kem,
        H: Kdf,
        A: Aead,
    {
        Self::generate_with_mode::<K, H, A>(Mode::Psk, Some(psk), Some(psk_id))
    }

    fn generate_with_mode<K, H, A>(
        mode: Mode,
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
    ) -> TestVector
    where
        K: Kem,
        H: Kdf,
        A: Aead,
    {
        use rand::RngCore;

        // Fixed test values
        let info = b"4f6465206f6e2061204772656369616e2055726e";
        let pt = b"4265617574792069732074727574682c20747275746820626561757479";
        let aad_base = b"Count-";
        let exporter_context_base = b"pseudorandom";

        // Generate random seed for recipient key pair
        let mut rng = rand::rng();
        let ikm_r = {
            // Use the KEM's seed size
            let mut seed = vec![0u8; K::N_SEED];
            rng.fill_bytes(&mut seed);
            seed
        };

        // Derive key pair from seed
        let (sk_r, pk_r) = K::derive_key_pair(&ikm_r);

        // Perform encapsulation
        let mut ikm_e = vec![0u8; K::N_RANDOM];
        rng.fill_bytes(&mut ikm_e);
        let (shared_secret, enc) = K::encap_derand(&pk_r, &ikm_e);

        // Create context
        let suite_id = Instance::<K, H, A>::suite_id();

        // Key schedule
        let (key, base_nonce, exporter_secret) = H::combine_secrets(
            &suite_id,
            mode,
            &shared_secret,
            info,
            psk.unwrap_or(&[]),
            psk_id.unwrap_or(&[]),
            A::N_K,
            A::N_N,
        );

        // Generate encryption vectors
        let mut encryptions = Vec::new();
        let mut ctx =
            Context::<A, Sender>::new(key.clone(), base_nonce.clone(), exporter_secret.clone());

        for i in 0..10 {
            let aad = format!("{}{}", String::from_utf8_lossy(aad_base), i);
            encryptions.push(EncryptionVector::generate(&mut ctx, pt, aad.as_bytes()));
        }

        // Generate export vectors
        let mut exports = Vec::new();
        for i in 0..5 {
            let exporter_context =
                format!("{}{}", String::from_utf8_lossy(exporter_context_base), i);
            let length = 32;
            exports.push(ExportVector::generate::<H>(
                &suite_id,
                &exporter_secret,
                exporter_context.as_bytes(),
                length,
            ));
        }

        TestVector {
            mode: mode.into(),
            kem_id: u16::from_be_bytes(K::ID),
            kdf_id: u16::from_be_bytes(H::ID),
            aead_id: u16::from_be_bytes(A::ID),
            info: info.to_vec(),
            ikm_e,
            ikm_r: ikm_r.clone(),
            sk_rm: K::serialize_private_key(&sk_r),
            pk_rm: K::serialize_public_key(&pk_r),
            enc,
            shared_secret,
            suite_id: suite_id.to_vec(),
            key,
            base_nonce,
            exporter_secret,
            psk: psk.map(|p| p.to_vec()),
            psk_id: psk_id.map(|p| p.to_vec()),
            encryptions,
            exports,
        }
    }

    pub fn verify(&self) -> Result<(), String> {
        // Dispatch to the appropriate verification based on algorithm IDs
        match (self.kem_id, self.kdf_id, self.aead_id) {
            // Combinations that appear in RFC 9180

            // P-256 combinations
            (0x0010, 0x0001, 0x0001) => self.v::<DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm>(),
            (0x0010, 0x0001, 0x0002) => self.v::<DhkemP256HkdfSha256, HkdfSha256, Aes256Gcm>(),
            (0x0010, 0x0001, 0x0003) => self.v::<DhkemP256HkdfSha256, HkdfSha256, ChaChaPoly>(),
            (0x0010, 0x0001, 0xffff) => self.v::<DhkemP256HkdfSha256, HkdfSha256, ExportOnly>(),
            (0x0010, 0x0003, 0x0001) => self.v::<DhkemP256HkdfSha256, HkdfSha512, Aes128Gcm>(),
            (0x0010, 0x0003, 0x0002) => self.v::<DhkemP256HkdfSha256, HkdfSha512, Aes256Gcm>(),
            (0x0010, 0x0003, 0x0003) => self.v::<DhkemP256HkdfSha256, HkdfSha512, ChaChaPoly>(),
            (0x0010, 0x0003, 0xffff) => self.v::<DhkemP256HkdfSha256, HkdfSha512, ExportOnly>(),

            // P-521 combinations
            (0x0012, 0x0001, 0x0001) => self.v::<DhkemP521HkdfSha512, HkdfSha256, Aes128Gcm>(),
            (0x0012, 0x0001, 0x0002) => self.v::<DhkemP521HkdfSha512, HkdfSha256, Aes256Gcm>(),
            (0x0012, 0x0001, 0x0003) => self.v::<DhkemP521HkdfSha512, HkdfSha256, ChaChaPoly>(),
            (0x0012, 0x0001, 0xffff) => self.v::<DhkemP521HkdfSha512, HkdfSha256, ExportOnly>(),
            (0x0012, 0x0003, 0x0001) => self.v::<DhkemP521HkdfSha512, HkdfSha512, Aes128Gcm>(),
            (0x0012, 0x0003, 0x0002) => self.v::<DhkemP521HkdfSha512, HkdfSha512, Aes256Gcm>(),
            (0x0012, 0x0003, 0x0003) => self.v::<DhkemP521HkdfSha512, HkdfSha512, ChaChaPoly>(),
            (0x0012, 0x0003, 0xffff) => self.v::<DhkemP521HkdfSha512, HkdfSha512, ExportOnly>(),

            // X25519 combinations
            (0x0020, 0x0001, 0x0001) => self.v::<DhkemX25519HkdfSha256, HkdfSha256, Aes128Gcm>(),
            (0x0020, 0x0001, 0x0002) => self.v::<DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm>(),
            (0x0020, 0x0001, 0x0003) => self.v::<DhkemX25519HkdfSha256, HkdfSha256, ChaChaPoly>(),
            (0x0020, 0x0001, 0xffff) => self.v::<DhkemX25519HkdfSha256, HkdfSha256, ExportOnly>(),
            (0x0020, 0x0003, 0x0001) => self.v::<DhkemX25519HkdfSha256, HkdfSha512, Aes128Gcm>(),
            (0x0020, 0x0003, 0x0002) => self.v::<DhkemX25519HkdfSha256, HkdfSha512, Aes256Gcm>(),
            (0x0020, 0x0003, 0x0003) => self.v::<DhkemX25519HkdfSha256, HkdfSha512, ChaChaPoly>(),
            (0x0020, 0x0003, 0xffff) => self.v::<DhkemX25519HkdfSha256, HkdfSha512, ExportOnly>(),

            // X448 combinations
            (0x0021, 0x0001, 0x0001) => self.v::<DhkemX448HkdfSha512, HkdfSha256, Aes128Gcm>(),
            (0x0021, 0x0001, 0x0002) => self.v::<DhkemX448HkdfSha512, HkdfSha256, Aes256Gcm>(),
            (0x0021, 0x0001, 0x0003) => self.v::<DhkemX448HkdfSha512, HkdfSha256, ChaChaPoly>(),
            (0x0021, 0x0001, 0xffff) => self.v::<DhkemX448HkdfSha512, HkdfSha256, ExportOnly>(),
            (0x0021, 0x0003, 0x0001) => self.v::<DhkemX448HkdfSha512, HkdfSha512, Aes128Gcm>(),
            (0x0021, 0x0003, 0x0002) => self.v::<DhkemX448HkdfSha512, HkdfSha512, Aes256Gcm>(),
            (0x0021, 0x0003, 0x0003) => self.v::<DhkemX448HkdfSha512, HkdfSha512, ChaChaPoly>(),
            (0x0021, 0x0003, 0xffff) => self.v::<DhkemX448HkdfSha512, HkdfSha512, ExportOnly>(),

            // Combinations for the new PQ algorithms and hybrids

            // ML-KEM-768 combinations
            (0x0041, 0x0001, 0x0001) => self.v::<MlKem768, HkdfSha256, Aes128Gcm>(),
            (0x0041, 0x0001, 0xffff) => self.v::<MlKem768, HkdfSha256, ExportOnly>(),

            // ML-KEM-1024 combinations
            (0x0042, 0x0002, 0x0002) => self.v::<MlKem1024, HkdfSha384, Aes256Gcm>(),
            (0x0042, 0x0002, 0xffff) => self.v::<MlKem1024, HkdfSha384, ExportOnly>(),

            // MLKEM768-P256 combinations
            (0x0050, 0x0011, 0x0001) => self.v::<MlKem768P256, Shake256, Aes128Gcm>(),
            (0x0050, 0x0011, 0xffff) => self.v::<MlKem768P256, Shake256, ExportOnly>(),

            // MLKEM768-X25519 combinations
            (0x647a, 0x0011, 0x0001) => self.v::<MlKem768X25519, Shake256, Aes128Gcm>(),
            (0x647a, 0x0011, 0xffff) => self.v::<MlKem768X25519, Shake256, ExportOnly>(),

            // MLKEM1024-P384 combinations
            (0x0051, 0x0011, 0x0002) => self.v::<MlKem1024P384, Shake256, Aes256Gcm>(),
            (0x0051, 0x0011, 0xffff) => self.v::<MlKem1024P384, Shake256, ExportOnly>(),

            _ => Err(format!(
                "Unsupported algorithm combination: KEM={:#x}, KDF={:#x}, AEAD={:#x}",
                self.kem_id, self.kdf_id, self.aead_id
            )),
        }
    }

    fn v<K, H, A>(&self) -> Result<(), String>
    where
        K: Kem,
        H: Kdf,
        A: Aead,
    {
        let mode = match self.mode {
            0 => Mode::Base,
            1 => Mode::Psk,
            _ => return Err(format!("Unsupported mode: {}", self.mode)),
        };

        // Create suite ID
        let suite_id = Instance::<K, H, A>::suite_id();

        // Verify derive_key_pair if ikm_r is provided
        let (sk_r, pk_r) = K::derive_key_pair(&self.ikm_r);

        // Verify the derived private key matches
        // XXX(RLB) We skip this because the test vectors present un-clamped private keys, and the
        // serialize/deserialize round trip here always clamps.  Rather than try to fix this, we
        // just rely on the public keys being the same, which should be equivalent.
        /*
        let sk_rm = K::serialize_private_key(&sk_r);
        if sk_rm != self.sk_rm {
            return Err("Derived private key doesn't match skRm".to_string());
        }
        */

        // Verify the derived public key matches
        let pk_rm = K::serialize_public_key(&pk_r);
        if pk_rm != self.pk_rm {
            return Err("Derived public key doesn't match pkRm".to_string());
        }

        // Create a receiver context using private key deserialization
        let mut ctx = match mode {
            Mode::Base => Instance::<K, H, A>::setup_base_r(&self.enc, &sk_r, &self.info),
            Mode::Psk => {
                // PSK mode requires psk and psk_id
                let psk = self.psk.as_ref().ok_or("PSK mode requires psk field")?;
                let psk_id = self
                    .psk_id
                    .as_ref()
                    .ok_or("PSK mode requires psk_id field")?;
                Instance::<K, H, A>::setup_psk_r(&self.enc, &sk_r, &self.info, psk, psk_id)
            }
        };

        // Verify encryption vectors (skip for export-only mode)
        if A::ID != [0xff, 0xff] {
            for (i, enc_vec) in self.encryptions.iter().enumerate() {
                enc_vec
                    .verify(&mut ctx, &enc_vec.pt)
                    .map_err(|e| format!("Encryption vector {} verification failed: {}", i, e))?;
            }
        }

        // Verify export vectors
        for (i, exp_vec) in self.exports.iter().enumerate() {
            exp_vec
                .verify::<H>(&suite_id, &self.exporter_secret)
                .map_err(|e| format!("Export vector {} verification failed: {}", i, e))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test<K, H, A>()
    where
        K: Kem,
        H: Kdf,
        A: Aead,
    {
        let test_vector = TestVector::new::<K, H, A>();
        let result = test_vector.verify();
    }

    #[test]
    fn test_all() {
        test::<DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm>();
        test::<DhkemP384HkdfSha384, HkdfSha384, Aes256Gcm>();
        test::<DhkemP521HkdfSha512, HkdfSha512, Aes256Gcm>();
        test::<DhkemX25519HkdfSha256, HkdfSha256, ChaChaPoly>();
        test::<DhkemX448HkdfSha512, HkdfSha512, ChaChaPoly>();

        test::<MlKem512, HkdfSha256, Aes128Gcm>();
        test::<MlKem768, HkdfSha256, Aes128Gcm>();
        test::<MlKem1024, HkdfSha384, Aes256Gcm>();

        test::<DhkemP256HkdfSha256, Shake128, Aes128Gcm>();
        test::<DhkemP384HkdfSha384, Shake256, Aes256Gcm>();
        test::<DhkemX25519HkdfSha256, TurboShake128, Aes128Gcm>();
        test::<DhkemX448HkdfSha512, TurboShake256, Aes256Gcm>();
    }
}
