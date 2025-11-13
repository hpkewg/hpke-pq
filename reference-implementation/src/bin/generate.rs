use std::process;

use hpke_ref::test_vectors::{TestVector, TestVectors};
use hpke_ref::*;

fn generate_test_vectors() -> TestVectors {
    let mut vectors = TestVectors::new();

    // Pure ML-KEM
    vectors.push(TestVector::new::<MlKem512, HkdfSha256, Aes128Gcm>());
    vectors.push(TestVector::new::<MlKem768, HkdfSha256, Aes128Gcm>());
    vectors.push(TestVector::new::<MlKem1024, HkdfSha384, Aes256Gcm>());

    // Hybrid KEMs
    vectors.push(TestVector::new::<MlKem768P256, HkdfSha256, Aes128Gcm>());
    vectors.push(TestVector::new::<MlKem768X25519, HkdfSha256, ChaChaPoly>());
    vectors.push(TestVector::new::<MlKem1024P384, HkdfSha384, Aes256Gcm>());

    // Single-stage KDFs
    vectors.push(TestVector::new::<DhkemP256HkdfSha256, Shake128, Aes128Gcm>());
    vectors.push(TestVector::new::<DhkemP384HkdfSha384, Shake256, Aes256Gcm>());
    vectors.push(TestVector::new::<
        DhkemX25519HkdfSha256,
        TurboShake128,
        ChaChaPoly,
    >());
    vectors.push(TestVector::new::<
        DhkemX448HkdfSha512,
        TurboShake256,
        ChaChaPoly,
    >());

    // Multiple new things at once, and mismatched levels
    vectors.push(TestVector::new::<MlKem768P256, Shake128, Aes256Gcm>());
    vectors.push(TestVector::new::<MlKem768X25519, Shake256, ChaChaPoly>());
    vectors.push(TestVector::new::<MlKem1024, TurboShake256, Aes128Gcm>());

    vectors
}

fn main() {
    // Generate test vectors
    let vectors = generate_test_vectors();

    // Serialize to JSON and output to stdout
    let json = match serde_json::to_string_pretty(&vectors) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error serializing test vectors: {}", e);
            process::exit(1);
        }
    };

    println!("{}", json);
}
