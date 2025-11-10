package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/hpke"
)

// TestVector represents a single HPKE test vector
type TestVector struct {
	Mode           uint8               `json:"mode"`
	KEMID          uint16              `json:"kem_id"`
	KDFID          uint16              `json:"kdf_id"`
	AEADID         uint16              `json:"aead_id"`
	Info           string              `json:"info"`
	IkmE           string              `json:"ikmE"`
	IkmR           string              `json:"ikmR"`
	SkRm           string              `json:"skRm"`
	PkRm           string              `json:"pkRm"`
	Enc            string              `json:"enc"`
	SharedSecret   string              `json:"shared_secret"`
	Key            string              `json:"key"`
	BaseNonce      string              `json:"base_nonce"`
	ExporterSecret string              `json:"exporter_secret"`
	PSK            *string             `json:"psk,omitempty"`
	PSKID          *string             `json:"psk_id,omitempty"`
	Encryptions    []EncryptionVector  `json:"encryptions"`
	Exports        []ExportVector      `json:"exports"`
}

// EncryptionVector represents encryption test data
type EncryptionVector struct {
	AAD   string `json:"aad"`
	CT    string `json:"ct"`
	Nonce string `json:"nonce"`
	PT    string `json:"pt"`
}

// ExportVector represents export test data
type ExportVector struct {
	ExporterContext string `json:"exporter_context"`
	Length          uint   `json:"L"`
	ExportedValue   string `json:"exported_value"`
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// isSupported checks if the KEM/KDF/AEAD combination is supported by Circl
func isSupported(kemID, kdfID, aeadID uint16) bool {
	// Check KEM support
	switch hpke.KEM(kemID) {
	case hpke.KEM_P256_HKDF_SHA256,
		hpke.KEM_P384_HKDF_SHA384,
		hpke.KEM_P521_HKDF_SHA512,
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KEM_X448_HKDF_SHA512,
		hpke.KEM_XWING:
		// These are supported
	default:
		return false
	}

	// Check KDF support
	switch hpke.KDF(kdfID) {
	case hpke.KDF_HKDF_SHA256,
		hpke.KDF_HKDF_SHA384,
		hpke.KDF_HKDF_SHA512:
		// These are supported
	default:
		return false
	}

	// Check AEAD support (0xFFFF is export-only mode, not supported for full test)
	if aeadID == 0xFFFF {
		return false
	}

	switch hpke.AEAD(aeadID) {
	case hpke.AEAD_AES128GCM,
		hpke.AEAD_AES256GCM,
		hpke.AEAD_ChaCha20Poly1305:
		// These are supported
	default:
		return false
	}

	return true
}

// verifyTestVector verifies a single test vector using Circl's HPKE implementation
func verifyTestVector(tv TestVector) error {
	// Create the HPKE suite
	suite := hpke.NewSuite(hpke.KEM(tv.KEMID), hpke.KDF(tv.KDFID), hpke.AEAD(tv.AEADID))

	// Decode the test vector data
	info, err := decodeHex(tv.Info)
	if err != nil {
		return fmt.Errorf("failed to decode info: %v", err)
	}

	skRm, err := decodeHex(tv.SkRm)
	if err != nil {
		return fmt.Errorf("failed to decode skRm: %v", err)
	}

	enc, err := decodeHex(tv.Enc)
	if err != nil {
		return fmt.Errorf("failed to decode enc: %v", err)
	}

	// Deserialize the private key
	scheme := hpke.KEM(tv.KEMID).Scheme()
	privKey, err := scheme.UnmarshalBinaryPrivateKey(skRm)
	if err != nil {
		return fmt.Errorf("failed to unmarshal private key: %v", err)
	}

	// Set up the receiver
	receiver, err := suite.NewReceiver(privKey, info)
	if err != nil {
		return fmt.Errorf("failed to create receiver: %v", err)
	}

	// Setup base mode
	opener, err := receiver.Setup(enc)
	if err != nil {
		return fmt.Errorf("failed to setup receiver: %v", err)
	}

	// Verify encryptions
	for i, encVec := range tv.Encryptions {
		aad, err := decodeHex(encVec.AAD)
		if err != nil {
			return fmt.Errorf("encryption[%d]: failed to decode aad: %v", i, err)
		}

		ct, err := decodeHex(encVec.CT)
		if err != nil {
			return fmt.Errorf("encryption[%d]: failed to decode ct: %v", i, err)
		}

		expectedPT, err := decodeHex(encVec.PT)
		if err != nil {
			return fmt.Errorf("encryption[%d]: failed to decode pt: %v", i, err)
		}

		// Decrypt
		pt, err := opener.Open(ct, aad)
		if err != nil {
			return fmt.Errorf("encryption[%d]: decryption failed: %v", i, err)
		}

		// Verify plaintext matches
		if !bytes.Equal(pt, expectedPT) {
			return fmt.Errorf("encryption[%d]: plaintext mismatch", i)
		}
	}

	return nil
}

func main() {
	// Read test vectors from stdin or file
	var reader io.Reader = os.Stdin
	if len(os.Args) > 1 {
		file, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		reader = file
	}

	// Parse JSON
	var testVectors []TestVector
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&testVectors); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	// Verify each test vector
	passed := 0
	failed := 0
	unsupported := 0

	for i, tv := range testVectors {
		// Check if this combination is supported
		if !isSupported(tv.KEMID, tv.KDFID, tv.AEADID) {
			unsupported++
			fmt.Printf("Vector %d: SKIPPED - unsupported algorithm combination: KEM=%#x, KDF=%#x, AEAD=%#x\n",
				i, tv.KEMID, tv.KDFID, tv.AEADID)
			continue
		}

		// Only support base mode (mode 0) for now
		if tv.Mode != 0 {
			unsupported++
			fmt.Printf("Vector %d: SKIPPED - unsupported mode: %d (only base mode 0 is implemented)\n", i, tv.Mode)
			continue
		}

		err := verifyTestVector(tv)
		if err != nil {
			failed++
			fmt.Printf("Vector %d: FAILED - %v\n", i, err)
		} else {
			passed++
			fmt.Printf("Vector %d: PASSED (mode=%d, kem=%#x, kdf=%#x, aead=%#x)\n",
				i, tv.Mode, tv.KEMID, tv.KDFID, tv.AEADID)
		}
	}

	// Print summary
	fmt.Println("\n=== Summary ===")
	fmt.Printf("Total test vectors: %d\n", len(testVectors))
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed)
	fmt.Printf("Unsupported: %d\n", unsupported)

	if failed > 0 {
		os.Exit(1)
	}
}
