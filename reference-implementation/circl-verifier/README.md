# Circl Test Vector Verifier using Circl

This Go module verifies HPKE test vectors using Cloudflare's
[Circl](https://github.com/cloudflare/circl) cryptographic library.

## Supported Algorithms

The verifier supports the following algorithm combinations that are available in Circl:

### KEMs (Key Encapsulation Mechanisms)
- P-256 with HKDF-SHA256 (0x0010)
- P-384 with HKDF-SHA384 (0x0011)
- P-521 with HKDF-SHA512 (0x0012)
- X25519 with HKDF-SHA256 (0x0020)
- X448 with HKDF-SHA512 (0x0021)
- X-Wing (X25519+ML-KEM-768 hybrid) (0x647a)

### KDFs (Key Derivation Functions)
- HKDF-SHA256 (0x0001)
- HKDF-SHA384 (0x0002)
- HKDF-SHA512 (0x0003)

### AEADs (Authenticated Encryption with Associated Data)
- AES-128-GCM (0x0001)
- AES-256-GCM (0x0002)
- ChaCha20-Poly1305 (0x0003)

## Limitations

- Only supports base mode (mode 0) HPKE operations
- Does not support PSK, Auth, or AuthPSK modes
- Does not support export-only mode (AEAD ID 0xFFFF)
- Skips test vectors for unsupported algorithm combinations

## Usage

### Build the verifier

```bash
cd circl-verifier
go build
```

### Run with test vectors

```bash
# From a file
./circl-verifier ../tests/rfc9180.json

# From stdin
cat ../tests/rfc9180.json | ./circl-verifier
```

### Run tests

```bash
go test
```

## Output

The verifier will print the status of each test vector:
- `PASSED`: Test vector verified successfully
- `SKIPPED`: Algorithm combination not supported by Circl
- `FAILED`: Verification failed (indicates a potential issue)

A summary is printed at the end showing counts of passed, failed, and unsupported vectors.
