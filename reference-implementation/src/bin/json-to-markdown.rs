use std::io::{self, Read};
use std::process;

use hpke_ref::test_vectors::{TestVector, TestVectors};

fn format_hex(data: &[u8], line_length: usize, label: &str) -> String {
    let hex_string = hex::encode(data);
    if hex_string.len() <= line_length {
        hex_string
    } else {
        let indent = " ".repeat(label.len());
        hex_string
            .chars()
            .collect::<Vec<_>>()
            .chunks(line_length)
            .enumerate()
            .map(|(i, chunk)| {
                let line = chunk.iter().collect::<String>();
                if i == 0 {
                    line
                } else {
                    format!("{}{}", indent, line)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn kem_name(kem_id: u16) -> &'static str {
    match kem_id {
        0x0010 => "DHKEM(P-256, HKDF-SHA256)",
        0x0011 => "DHKEM(P-384, HKDF-SHA384)",
        0x0012 => "DHKEM(P-521, HKDF-SHA512)",
        0x0020 => "DHKEM(X25519, HKDF-SHA256)",
        0x0021 => "DHKEM(X448, HKDF-SHA512)",
        0x0040 => "ML-KEM-512",
        0x0041 => "ML-KEM-768",
        0x0042 => "ML-KEM-1024",
        0x0050 => "QSF-P256-MLKEM768",
        0x0051 => "QSF-X25519-MLKEM768",
        0x0052 => "QSF-P384-MLKEM1024",
        _ => "Unknown KEM",
    }
}

fn kdf_name(kdf_id: u16) -> &'static str {
    match kdf_id {
        0x0001 => "HKDF-SHA256",
        0x0002 => "HKDF-SHA384",
        0x0003 => "HKDF-SHA512",
        0x0010 => "SHAKE256",
        _ => "Unknown KDF",
    }
}

fn aead_name(aead_id: u16) -> &'static str {
    match aead_id {
        0x0001 => "AES-128-GCM",
        0x0002 => "AES-256-GCM",
        0x0003 => "ChaCha20Poly1305",
        0xffff => "Export-Only",
        _ => "Unknown AEAD",
    }
}

fn convert_test_vector_to_markdown(tv: &TestVector) -> String {
    let mut output = String::new();

    // Section header
    let suite_name = format!(
        "{}, {}, {}",
        kem_name(tv.kem_id),
        kdf_name(tv.kdf_id),
        aead_name(tv.aead_id)
    );
    output.push_str(&format!("## {}\n\n", suite_name));

    // Setup information section
    let setup_section = if tv.mode == 1 {
        "PSK Setup Information"
    } else {
        "Base Setup Information"
    };
    output.push_str(&format!("### {}\n", setup_section));
    output.push_str("~~~\n");
    output.push_str(&format!("mode: {}\n", tv.mode));
    output.push_str(&format!("kem_id: {}\n", tv.kem_id));
    output.push_str(&format!("kdf_id: {}\n", tv.kdf_id));
    output.push_str(&format!("aead_id: {}\n", tv.aead_id));
    output.push_str(&format!("info: {}\n", hex::encode(&tv.info)));

    if !tv.ikm_r.is_empty() {
        output.push_str(&format!("ikmR: {}\n", format_hex(&tv.ikm_r, 64, "ikmR: ")));
    }

    output.push_str(&format!("pkRm: {}\n", format_hex(&tv.pk_rm, 64, "pkRm: ")));

    if !tv.sk_rm.is_empty() {
        output.push_str(&format!("skRm: {}\n", format_hex(&tv.sk_rm, 64, "skRm: ")));
    }

    output.push_str(&format!("enc: {}\n", format_hex(&tv.enc, 64, "enc: ")));
    output.push_str(&format!(
        "shared_secret: {}\n",
        format_hex(&tv.shared_secret, 64, "shared_secret: ")
    ));

    // Skip key_schedule_context and secret for now as they're not in our test vectors

    output.push_str(&format!("key: {}\n", format_hex(&tv.key, 64, "key: ")));
    output.push_str(&format!(
        "base_nonce: {}\n",
        format_hex(&tv.base_nonce, 64, "base_nonce: ")
    ));
    output.push_str(&format!(
        "exporter_secret: {}\n",
        format_hex(&tv.exporter_secret, 64, "exporter_secret: ")
    ));

    // PSK fields if present
    if let Some(psk) = &tv.psk {
        output.push_str(&format!("psk: {}\n", format_hex(psk, 64, "psk: ")));
    }
    if let Some(psk_id) = &tv.psk_id {
        output.push_str(&format!("psk_id: {}\n", format_hex(psk_id, 64, "psk_id: ")));
    }

    output.push_str("~~~\n\n");

    // Encryption vectors (skip for export-only)
    if tv.aead_id != 0xffff && !tv.encryptions.is_empty() {
        output.push_str("#### Encryptions\n");
        output.push_str("~~~\n");

        for (i, enc_vec) in tv.encryptions.iter().enumerate() {
            if i > 0 {
                output.push_str("\n");
            }
            output.push_str(&format!("sequence number: {}\n", i));
            output.push_str(&format!("pt: {}\n", hex::encode(&enc_vec.pt)));
            output.push_str(&format!("aad: {}\n", hex::encode(&enc_vec.aad)));
            output.push_str(&format!("nonce: {}\n", hex::encode(&enc_vec.nonce)));
            output.push_str(&format!("ct: {}\n", format_hex(&enc_vec.ct, 64, "ct: ")));
        }

        output.push_str("~~~\n\n");
    }

    // Export vectors
    if !tv.exports.is_empty() {
        output.push_str("#### Exported Values\n");
        output.push_str("~~~\n");

        for (i, exp_vec) in tv.exports.iter().enumerate() {
            if i > 0 {
                output.push_str("\n");
            }
            output.push_str(&format!(
                "exporter_context: {}\n",
                hex::encode(&exp_vec.exporter_context)
            ));
            output.push_str(&format!("L: {}\n", exp_vec.length));
            output.push_str(&format!(
                "exported_value: {}\n",
                format_hex(&exp_vec.exported_value, 64, "exported_value: ")
            ));
        }

        output.push_str("~~~\n\n");
    }

    output
}

fn main() {
    // Read JSON from stdin
    let mut json_content = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut json_content) {
        eprintln!("Error reading from stdin: {}", e);
        process::exit(1);
    }

    // Parse JSON
    let test_vectors: TestVectors = match serde_json::from_str(&json_content) {
        Ok(vectors) => vectors,
        Err(e) => {
            eprintln!("Error parsing JSON: {}", e);
            process::exit(1);
        }
    };

    // Convert to Markdown and write to stdout
    for test_vector in &test_vectors {
        print!("{}", convert_test_vector_to_markdown(test_vector));
    }
}
