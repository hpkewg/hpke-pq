#!/bin/bash

set -e  # Exit on any error

# Script to regenerate JSON and markdown test vector files
cd reference-implementation

echo "Generating test vectors to temporary file..."
TEMP_VECTORS=$(mktemp)
trap "rm -f $TEMP_VECTORS" EXIT

cargo run --bin generate-test-vectors -- > "$TEMP_VECTORS"

echo "Verifying test vectors with Rust verifier..."
cargo run --bin verify-test-vectors -- < "$TEMP_VECTORS"

echo "All verifications passed! Writing final files..."
cp "$TEMP_VECTORS" ../test-vectors.json

echo "Converting to markdown..."
cargo run --bin json-to-markdown -- < ../test-vectors.json > ../test-vectors.md

echo "Test vectors successfully updated and verified!"
