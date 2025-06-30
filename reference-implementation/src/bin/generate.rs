use std::fs;
use std::path::PathBuf;
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
    vectors.push(TestVector::new::<QsfP256MlKem768, Shake256, Aes128Gcm>());

    // 4. QSF-X25519-MLKEM768 + SHAKE256 + AES-128-GCM
    vectors.push(TestVector::new::<QsfX25519MlKem768, Shake256, Aes128Gcm>());

    // 5. QSF-P384-MLKEM1024 + SHAKE256 + AES-256-GCM
    vectors.push(TestVector::new::<QsfP384MlKem1024, Shake256, Aes256Gcm>());

    vectors
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <output.json>", args[0]);
        process::exit(1);
    }

    let output_path = PathBuf::from(&args[1]);

    // Generate test vectors
    let vectors = generate_test_vectors();

    // Serialize to JSON
    let json = match serde_json::to_string_pretty(&vectors) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error serializing test vectors: {}", e);
            process::exit(1);
        }
    };

    // Write to file
    if let Err(e) = fs::write(&output_path, json) {
        eprintln!("Error writing to {}: {}", output_path.display(), e);
        process::exit(1);
    }

    println!(
        "Generated {} test vectors to {}",
        vectors.len(),
        output_path.display()
    );
}
