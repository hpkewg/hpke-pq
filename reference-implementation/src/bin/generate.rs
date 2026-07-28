use std::process;

use hpke_ref::test_vectors::{TestVector, TestVectors};
use hpke_ref::*;

fn generate_test_vectors() -> TestVectors {
    // PSK and PSK_ID from RFC 9180.
    let psk =
        hex::decode("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82").unwrap();
    let psk_id = hex::decode("456e6e796e20447572696e206172616e204d6f726961").unwrap();

    let mut vectors = TestVectors::new();

    // Pure ML-KEM
    vectors.push(TestVector::new::<MlKem512, HkdfSha256, Aes128Gcm>());
    vectors.push(TestVector::new_psk::<MlKem512, HkdfSha256, Aes128Gcm>(
        &psk, &psk_id,
    ));

    vectors.push(TestVector::new::<MlKem768, HkdfSha256, Aes128Gcm>());
    vectors.push(TestVector::new_psk::<MlKem768, HkdfSha256, Aes128Gcm>(
        &psk, &psk_id,
    ));

    vectors.push(TestVector::new::<MlKem1024, HkdfSha384, Aes256Gcm>());
    vectors.push(TestVector::new_psk::<MlKem1024, HkdfSha384, Aes256Gcm>(
        &psk, &psk_id,
    ));

    // Hybrid KEMs
    vectors.push(TestVector::new::<MlKem768P256, HkdfSha256, Aes128Gcm>());
    vectors.push(TestVector::new_psk::<MlKem768P256, HkdfSha256, Aes128Gcm>(
        &psk, &psk_id,
    ));

    vectors.push(TestVector::new::<MlKem768X25519, HkdfSha256, ChaChaPoly>());
    vectors.push(TestVector::new_psk::<MlKem768X25519, HkdfSha256, ChaChaPoly>(&psk, &psk_id));

    vectors.push(TestVector::new::<MlKem1024P384, HkdfSha384, Aes256Gcm>());
    vectors.push(TestVector::new_psk::<MlKem1024P384, HkdfSha384, Aes256Gcm>(
        &psk, &psk_id,
    ));

    // Single-stage KDFs
    vectors.push(TestVector::new::<DhkemP256HkdfSha256, Shake128, Aes128Gcm>());
    vectors.push(TestVector::new_psk::<
        DhkemP256HkdfSha256,
        Shake128,
        Aes128Gcm,
    >(&psk, &psk_id));

    vectors.push(TestVector::new::<DhkemP384HkdfSha384, Shake256, Aes256Gcm>());
    vectors.push(TestVector::new_psk::<
        DhkemP384HkdfSha384,
        Shake256,
        Aes256Gcm,
    >(&psk, &psk_id));

    vectors.push(TestVector::new::<
        DhkemX25519HkdfSha256,
        TurboShake128,
        ChaChaPoly,
    >());
    vectors.push(TestVector::new_psk::<
        DhkemX25519HkdfSha256,
        TurboShake128,
        ChaChaPoly,
    >(&psk, &psk_id));

    vectors.push(TestVector::new::<
        DhkemX448HkdfSha512,
        TurboShake256,
        ChaChaPoly,
    >());
    vectors.push(TestVector::new_psk::<
        DhkemX448HkdfSha512,
        TurboShake256,
        ChaChaPoly,
    >(&psk, &psk_id));

    // Multiple new things at once, and mismatched levels
    vectors.push(TestVector::new::<MlKem768P256, Shake128, Aes256Gcm>());
    vectors.push(TestVector::new_psk::<MlKem768P256, Shake128, Aes256Gcm>(
        &psk, &psk_id,
    ));

    vectors.push(TestVector::new::<MlKem768X25519, Shake256, ChaChaPoly>());
    vectors.push(TestVector::new_psk::<MlKem768X25519, Shake256, ChaChaPoly>(
        &psk, &psk_id,
    ));

    vectors.push(TestVector::new::<MlKem1024, TurboShake256, Aes128Gcm>());
    vectors.push(TestVector::new_psk::<MlKem768X25519, Shake256, ChaChaPoly>(
        &psk, &psk_id,
    ));

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
