#!/usr/bin/env bash
# Wazuh Rust Backend CI/CD Quality & Validation Suite (Modern replacement for src/ci)
set -euo pipefail

echo "==============================================================="
echo " Wazuh Next-Gen Rust SIEM - Workspace CI & Verification Suite"
echo "==============================================================="

echo "[1/2] Checking workspace compilation across all 30 member crates..."
cargo check --workspace

echo "[2/2] Running workspace unit test suite..."
cargo test --workspace

echo "==============================================================="
echo " [SUCCESS] CI Quality Verification Complete: ALL CHECKS PASSED!"
echo "==============================================================="
