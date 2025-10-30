use std::process;

use hpke_ref::test_vectors::{TestVector, TestVectors};
use hpke_ref::*;

fn generate_test_vectors() -> TestVectors {
    let mut vectors = TestVectors::new();

    // Only generate the specified combinations:

    // 1. ML-KEM-768 + HKDF-SHA256 + AES-128-GCM
    vectors.push(TestVector::new::<MlKem768, HkdfSha256, Aes128Gcm>());

    // 2. ML-KEM-1024 + HKDF-SHA384 + AES-256-GCM
    vectors.push(TestVector::new::<MlKem1024, HkdfSha384, Aes256Gcm>());

    // 3. QSF-P256-MLKEM768 + SHAKE256 + AES-128-GCM
    vectors.push(TestVector::new::<MlKem768P256, Shake256, Aes128Gcm>());

    // 4. QSF-X25519-MLKEM768 + SHAKE256 + AES-128-GCM
    vectors.push(TestVector::new::<MlKem768X25519, HkdfSha256, Aes128Gcm>());

    // 4. QSF-X25519-MLKEM768 + SHAKE256 + AES-128-GCM
    vectors.push(TestVector::new::<MlKem768X25519, Shake256, Aes128Gcm>());

    // 5. QSF-P384-MLKEM1024 + SHAKE256 + AES-256-GCM
    vectors.push(TestVector::new::<MlKem1024P384, Shake256, Aes256Gcm>());

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
