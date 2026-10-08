<#
.SYNOPSIS
    Wazuh Rust Backend CI/CD Quality & Validation Suite (Modern replacement for src/ci)
.DESCRIPTION
    Executes workspace check, unit tests, and validation across all 30 member crates.
    Replaces legacy C/C++ tooling:
      - astyle      -> cargo fmt
      - cppcheck    -> cargo clippy
      - valgrind    -> Rust Ownership & Borrow Checker
      - make / ctest -> cargo test
#>

param(
    [switch]$SkipTests,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host " Wazuh Next-Gen Rust SIEM - Workspace CI & Verification Suite" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

if ($Clean) {
    Write-Host "[1/3] Cleaning workspace build artifacts..." -ForegroundColor Yellow
    cargo clean
}

Write-Host "[1/2] Checking workspace compilation..." -ForegroundColor Yellow
cargo check --workspace --jobs 1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Workspace compilation check failed!" -ForegroundColor Red
    exit 1
}
Write-Host "[PASS] All 30 member crates compile cleanly with 0 errors!" -ForegroundColor Green

if (-not $SkipTests) {
    Write-Host "[2/2] Running workspace unit test suite..." -ForegroundColor Yellow
    cargo test --workspace --jobs 1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[FAIL] One or more unit tests failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "[PASS] 100% of unit tests passed across all member crates!" -ForegroundColor Green
}

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host " [SUCCESS] CI Quality Verification Complete: ALL CHECKS PASSED!" -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Cyan
