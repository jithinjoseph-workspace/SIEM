#!/bin/bash
# ==============================================================================
# Wazuh Linux Agent - Multi-Package Generation Pipeline
# Mirrors official Wazuh package builder (packages/build.sh & generate_package.sh)
# Generates: .deb (Debian/Ubuntu), .rpm (RHEL/CentOS/Rocky), and .tar.gz (Universal)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="${SCRIPT_DIR}/.."
OUTPUT_DIR="${CRATE_DIR}/dist"
VERSION="4.14.7"
ARCH="x86_64"
DEB_ARCH="amd64"

echo "==============================================================="
echo "   Building Wazuh Next-Gen Linux Agent Packages (v${VERSION})   "
echo "==============================================================="

mkdir -p "${OUTPUT_DIR}"

# 1. Compile release binary
echo "[1/4] Compiling siem-agent-linux in release mode..."
cargo build --release --package siem-agent-linux --manifest-path "${CRATE_DIR}/Cargo.toml"
BINARY="${CRATE_DIR}/../../target/release/siem-agent-linux"

if [ ! -f "${BINARY}" ]; then
    echo "[-] Error: Release binary not found at ${BINARY}"
    exit 1
fi

# 2. Build Universal Standalone Tarball (.tar.gz)
echo "[2/4] Packaging Universal Standalone Tarball (.tar.gz)..."
TAR_STAGING="${OUTPUT_DIR}/wazuh-agent-${VERSION}-${ARCH}"
rm -rf "${TAR_STAGING}"
mkdir -p "${TAR_STAGING}/bin" "${TAR_STAGING}/etc" "${TAR_STAGING}/init"
cp "${BINARY}" "${TAR_STAGING}/bin/siem-agent-linux"
cp "${CRATE_DIR}/init/wazuh-rust-agent.service" "${TAR_STAGING}/init/"
cp "${CRATE_DIR}/install.sh" "${TAR_STAGING}/"

TARBALL_NAME="wazuh-agent-${VERSION}-linux-${ARCH}.tar.gz"
tar -czf "${OUTPUT_DIR}/${TARBALL_NAME}" -C "${OUTPUT_DIR}" "wazuh-agent-${VERSION}-${ARCH}"
rm -rf "${TAR_STAGING}"
echo "[✓] Generated: ${OUTPUT_DIR}/${TARBALL_NAME}"

# 3. Build Debian / Ubuntu Package (.deb)
echo "[3/4] Building Debian/Ubuntu Package (.deb)..."
DEB_STAGING="${OUTPUT_DIR}/deb-staging"
rm -rf "${DEB_STAGING}"
mkdir -p "${DEB_STAGING}/DEBIAN"
mkdir -p "${DEB_STAGING}/var/ossec/bin"
mkdir -p "${DEB_STAGING}/lib/systemd/system"

# Copy control files
cat <<EOF > "${DEB_STAGING}/DEBIAN/control"
Package: wazuh-agent
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: Wazuh Rust Team <info@wazuh.com>
Depends: libc6 (>= 2.17), systemd, procps, iptables | ufw
Description: Wazuh Next-Gen Endpoint Security Agent (Rust)
 Wazuh provides comprehensive security visibility, log analysis,
 file integrity monitoring, CIS benchmark auditing, and active response.
EOF

cp "${SCRIPT_DIR}/debs/postinst" "${DEB_STAGING}/DEBIAN/postinst"
cp "${SCRIPT_DIR}/debs/prerm" "${DEB_STAGING}/DEBIAN/prerm"
cp "${SCRIPT_DIR}/debs/postrm" "${DEB_STAGING}/DEBIAN/postrm"
chmod 755 "${DEB_STAGING}/DEBIAN/"*

cp "${BINARY}" "${DEB_STAGING}/var/ossec/bin/siem-agent-linux"
chmod 750 "${DEB_STAGING}/var/ossec/bin/siem-agent-linux"
cp "${CRATE_DIR}/init/wazuh-rust-agent.service" "${DEB_STAGING}/lib/systemd/system/wazuh-rust-agent.service"

DEB_NAME="wazuh-agent_${VERSION}_${DEB_ARCH}.deb"
if command -v dpkg-deb > /dev/null 2>&1; then
    dpkg-deb --build "${DEB_STAGING}" "${OUTPUT_DIR}/${DEB_NAME}"
    echo "[✓] Generated: ${OUTPUT_DIR}/${DEB_NAME}"
else
    echo "[i] dpkg-deb not present on host. Staging prepared at ${DEB_STAGING}."
fi

# 4. Build RHEL / CentOS / Rocky / Fedora Package (.rpm)
echo "[4/4] Preparing RPM Package Staging (.rpm)..."
RPM_SPEC="${SCRIPT_DIR}/rpms/wazuh-agent.spec"
if command -v rpmbuild > /dev/null 2>&1; then
    RPM_TOPDIR="${OUTPUT_DIR}/rpmbuild"
    mkdir -p "${RPM_TOPDIR}/"{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    cp "${BINARY}" "${RPM_TOPDIR}/SOURCES/siem-agent-linux"
    cp "${CRATE_DIR}/init/wazuh-rust-agent.service" "${RPM_TOPDIR}/SOURCES/wazuh-rust-agent.service"
    rpmbuild --define "_topdir ${RPM_TOPDIR}" -bb "${RPM_SPEC}"
    cp "${RPM_TOPDIR}"/RPMS/*/*.rpm "${OUTPUT_DIR}/" || true
    echo "[✓] RPM package built in ${OUTPUT_DIR}/"
else
    echo "[i] rpmbuild tool not present on host. RPM SPEC and scripts ready at ${SCRIPT_DIR}/rpms."
fi

# 5. Generate SHA-512 Checksums (matching Wazuh packages/build.sh)
echo "[+] Generating SHA-512 checksums..."
cd "${OUTPUT_DIR}"
for f in *.tar.gz *.deb *.rpm; do
    if [ -f "$f" ]; then
        if command -v sha512sum > /dev/null 2>&1; then
            sha512sum "$f" > "${f}.sha512"
            echo "    SHA512 ($f): $(cat ${f}.sha512 | awk '{print $1}')"
        fi
    fi
done

echo "==============================================================="
echo "   Package Pipeline Completed Successfully!                    "
echo "   Distribution Artifacts available in: ${OUTPUT_DIR}          "
echo "==============================================================="
