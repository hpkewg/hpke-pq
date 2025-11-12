use std::io::{self, Read};
use std::process;

use hpke_ref::test_vectors::{TestVector, TestVectors};

const MAX_LINE_LENGTH: usize = 70;

fn format_hex(data: &[u8], label: &str) -> String {
    let hex_string = hex::encode(data);

    // Check if the entire hex string fits on one line with the label
    if label.len() + hex_string.len() <= MAX_LINE_LENGTH {
        return hex_string;
    }

    // Calculate how many hex characters can fit on the first line after the label
    let first_line_chars = MAX_LINE_LENGTH - label.len();

    // Calculate how many hex characters can fit on subsequent lines
    let indent_length = label.len();
    let subsequent_line_chars = MAX_LINE_LENGTH - indent_length;

    let mut result = String::new();
    let mut chars = hex_string.chars();

    // First line - take as many characters as will fit after the label
    let first_line: String = chars.by_ref().take(first_line_chars).collect();
    result.push_str(&first_line);

    // Subsequent lines - indent and take appropriate number of characters
    let indent = " ".repeat(indent_length);
    let remaining: String = chars.collect();

    for chunk in remaining
        .chars()
        .collect::<Vec<_>>()
        .chunks(subsequent_line_chars)
    {
        result.push('\n');
        result.push_str(&indent);
        result.push_str(&chunk.iter().collect::<String>());
    }

    result
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
        0x0050 => "MLKEM768-P256",
        0x0051 => "MLKEM1024-P384",
        0x647a => "MLKEM768-X25519",
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
    output.push_str(&format!("info: {}\n", format_hex(&tv.info, "info: ")));

    if !tv.ikm_r.is_empty() {
        output.push_str(&format!("ikmR: {}\n", format_hex(&tv.ikm_r, "ikmR: ")));
    }

    output.push_str(&format!("pkRm: {}\n", format_hex(&tv.pk_rm, "pkRm: ")));

    if !tv.sk_rm.is_empty() {
        output.push_str(&format!("skRm: {}\n", format_hex(&tv.sk_rm, "skRm: ")));
    }

    output.push_str(&format!("enc: {}\n", format_hex(&tv.enc, "enc: ")));
    output.push_str(&format!(
        "shared_secret: {}\n",
        format_hex(&tv.shared_secret, "shared_secret: ")
    ));

    // Skip key_schedule_context and secret for now as they're not in our test vectors

    output.push_str(&format!("key: {}\n", format_hex(&tv.key, "key: ")));
    output.push_str(&format!(
        "base_nonce: {}\n",
        format_hex(&tv.base_nonce, "base_nonce: ")
    ));
    output.push_str(&format!(
        "exporter_secret: {}\n",
        format_hex(&tv.exporter_secret, "exporter_secret: ")
    ));

    // PSK fields if present
    if let Some(psk) = &tv.psk {
        output.push_str(&format!("psk: {}\n", format_hex(psk, "psk: ")));
    }
    if let Some(psk_id) = &tv.psk_id {
        output.push_str(&format!("psk_id: {}\n", format_hex(psk_id, "psk_id: ")));
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
            output.push_str(&format!("pt: {}\n", format_hex(&enc_vec.pt, "pt: ")));
            output.push_str(&format!("aad: {}\n", format_hex(&enc_vec.aad, "aad: ")));
            output.push_str(&format!(
                "nonce: {}\n",
                format_hex(&enc_vec.nonce, "nonce: ")
            ));
            output.push_str(&format!("ct: {}\n", format_hex(&enc_vec.ct, "ct: ")));
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
                format_hex(&exp_vec.exported_value, "exported_value: ")
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
