use std::io::{self, Read};
use std::process;

use hpke_ref::test_vectors::TestVectors;

pub struct VerificationResult {
    pub passed: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

fn verify_test_vectors(vectors: &TestVectors) -> VerificationResult {
    let mut passed = 0;
    let mut failed = 0;
    let mut errors = Vec::new();

    for (i, vector) in vectors.iter().enumerate() {
        match vector.verify() {
            Ok(()) => {
                passed += 1;
            }
            Err(e) => {
                errors.push(format!(
                    "Test vector {} failed (mode={}, kem_id={}, kdf_id={}, aead_id={}): {}",
                    i, vector.mode, vector.kem_id, vector.kdf_id, vector.aead_id, e
                ));
                failed += 1;
            }
        }
    }

    VerificationResult {
        passed,
        failed,
        errors,
    }
}

fn main() {
    // Read JSON from stdin
    let mut json_content = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut json_content) {
        eprintln!("Error reading from stdin: {}", e);
        process::exit(1);
    }

    // Parse the JSON
    let vectors: TestVectors = match serde_json::from_str(&json_content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing JSON: {}", e);
            process::exit(1);
        }
    };

    println!("Verifying {} test vectors...", vectors.len());

    // Verify the test vectors
    let result = verify_test_vectors(&vectors);

    // Print errors
    for error in &result.errors {
        eprintln!("{}", error);
    }

    // Print summary
    println!("\nResults:");
    println!("  Passed: {}", result.passed);
    println!("  Failed: {}", result.failed);
    println!("  Total:  {}", vectors.len());

    if result.failed > 0 {
        process::exit(1);
    }
}
