#!/bin/bash
# Cross-builds the Windows agent (wazuh-agent.exe, crate siem-winagent) in WSL
# and publishes it to data/agent-dist/windows, where siem-api serves it to the
# deploy command. WSL is used because the vendored OpenSSL needs a full perl/make.
# Needs in WSL: rustup target x86_64-pc-windows-gnu and mingw-w64 (x86_64-w64-mingw32-gcc).
set -e
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR=~/rs-wtarget
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
export AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
~/.cargo/bin/cargo build --release --target x86_64-pc-windows-gnu -p siem-winagent
mkdir -p data/agent-dist/windows
cp "$CARGO_TARGET_DIR/x86_64-pc-windows-gnu/release/wazuh-agent.exe" data/agent-dist/windows/wazuh-agent.exe
echo "[OK] data/agent-dist/windows/wazuh-agent.exe updated"
