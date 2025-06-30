use hpke_ref::test_vectors::*;
use std::fs;

#[test]
fn rfc9180_test_vectors() {
    // Load the RFC 9180 test vectors
    let test_vectors_json = fs::read_to_string("tests/rfc9180.json")
        .expect("Failed to read RFC 9180 test vectors file");

    let test_vectors: Vec<TestVector> = serde_json::from_str(&test_vectors_json)
        .expect("Failed to parse RFC 9180 test vectors JSON");

    println!("Loaded {} RFC 9180 test vectors", test_vectors.len());

    let mut successful_verifications = 0;
    let mut failed_verifications = 0;
    let mut unsupported_combinations = 0;

    for (i, test_vector) in test_vectors.iter().enumerate() {
        println!(
            "Testing vector {}: mode={}, kem_id={:#x}, kdf_id={:#x}, aead_id={:#x}",
            i, test_vector.mode, test_vector.kem_id, test_vector.kdf_id, test_vector.aead_id
        );

        match test_vector.verify() {
            Ok(()) => {
                successful_verifications += 1;
                println!("  ✓ Vector {} verified successfully", i);
            }
            Err(e) if e.contains("Unsupported algorithm combination") => {
                unsupported_combinations += 1;
                println!(
                    "  ⚠ Vector {} uses unsupported algorithm combination: {}",
                    i, e
                );
            }
            Err(e) if e.contains("Unsupported mode") => {
                unsupported_combinations += 1;
                println!("  ⚠ Vector {} uses unsupported mode: {}", i, e);
            }
            Err(e) => {
                failed_verifications += 1;
                println!("  ✗ Vector {} verification failed: {}", i, e);
            }
        }
    }

    println!("\nSummary:");
    println!("  Total test vectors: {}", test_vectors.len());
    println!("  Successful verifications: {}", successful_verifications);
    println!("  Failed verifications: {}", failed_verifications);
    println!("  Unsupported combinations: {}", unsupported_combinations);

    // We expect some unsupported combinations since we don't implement all algorithms,
    // but we should have no failures for supported combinations
    assert_eq!(
        failed_verifications, 0,
        "Some supported algorithm combinations failed verification"
    );

    // We should successfully verify at least some test vectors
    assert!(
        successful_verifications > 0,
        "No test vectors were successfully verified"
    );
}
