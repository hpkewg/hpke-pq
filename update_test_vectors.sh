#!/bin/bash

# Script to regenerate JSON and markdown test vector files
cd reference-implementation
cargo run --bin generate-test-vectors -- >../test-vectors.json
cargo run --bin json-to-markdown -- <../test-vectors.json >../test-vectors.md
