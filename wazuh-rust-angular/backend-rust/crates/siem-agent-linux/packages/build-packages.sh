#!/bin/bash
# ProVigil Linux Agent - Multi-Package Generation Pipeline
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="${SCRIPT_DIR}/.."
OUTPUT_DIR="${CRATE_DIR}/dist"
VERSION="1.0.0"
ARCH="x86_64"
DEB_ARCH="amd64"

echo "==============================================================="
echo "   Building ProVigil Linux Agent Packages (v${VERSION})        "
echo "==============================================================="

mkdir -p "${OUTPUT_DIR}"

echo "[1/4] Compiling siem-agent-linux in release mode..."
cargo build --release --package siem-agent-linux --manifest-path "${CRATE_DIR}/Cargo.toml"
BINARY="${CRATE_DIR}/../../target/release/siem-agent-linux"

if [ ! -f "${BINARY}" ]; then
    echo "[-] Error: Release binary not found at ${BINARY}"
    exit 1
fi

echo "[2/4] Packaging Universal Standalone Tarball (.tar.gz)..."
TAR_STAGING="${OUTPUT_DIR}/provigil-agent-${VERSION}-${ARCH}"
rm -rf "${TAR_STAGING}"
mkdir -p "${TAR_STAGING}/bin" "${TAR_STAGING}/etc" "${TAR_STAGING}/init"
cp "${BINARY}" "${TAR_STAGING}/bin/siem-agent-linux"
cp "${CRATE_DIR}/init/provigil-agent.service" "${TAR_STAGING}/init/"
cp "${CRATE_DIR}/install.sh" "${TAR_STAGING}/"

TARBALL_NAME="provigil-agent-${VERSION}-linux-${ARCH}.tar.gz"
tar -czf "${OUTPUT_DIR}/${TARBALL_NAME}" -C "${OUTPUT_DIR}" "provigil-agent-${VERSION}-${ARCH}"
rm -rf "${TAR_STAGING}"
echo "[+] Generated: ${OUTPUT_DIR}/${TARBALL_NAME}"

echo "[3/4] Building Debian/Ubuntu Package (.deb)..."
DEB_STAGING="${OUTPUT_DIR}/deb-staging"
rm -rf "${DEB_STAGING}"
mkdir -p "${DEB_STAGING}/DEBIAN"
mkdir -p "${DEB_STAGING}/opt/provigil-agent/bin"
mkdir -p "${DEB_STAGING}/lib/systemd/system"

cat <<EOF > "${DEB_STAGING}/DEBIAN/control"
Package: provigil-agent
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: ProVigil Security <support@provigil.io>
Depends: libc6 (>= 2.17), systemd, procps, iptables | ufw
Description: ProVigil Linux Endpoint Security Agent
 ProVigil provides endpoint security visibility, log analysis,
 file integrity monitoring, CIS benchmark auditing, and active response.
EOF

cp "${SCRIPT_DIR}/debs/postinst" "${DEB_STAGING}/DEBIAN/postinst"
cp "${SCRIPT_DIR}/debs/prerm" "${DEB_STAGING}/DEBIAN/prerm"
cp "${SCRIPT_DIR}/debs/postrm" "${DEB_STAGING}/DEBIAN/postrm"
chmod 755 "${DEB_STAGING}/DEBIAN/"*

cp "${BINARY}" "${DEB_STAGING}/opt/provigil-agent/bin/siem-agent-linux"
chmod 750 "${DEB_STAGING}/opt/provigil-agent/bin/siem-agent-linux"
cp "${CRATE_DIR}/init/provigil-agent.service" "${DEB_STAGING}/lib/systemd/system/provigil-agent.service"

DEB_NAME="provigil-agent_${VERSION}_${DEB_ARCH}.deb"
if command -v dpkg-deb > /dev/null 2>&1; then
    dpkg-deb --build "${DEB_STAGING}" "${OUTPUT_DIR}/${DEB_NAME}"
    echo "[+] Generated: ${OUTPUT_DIR}/${DEB_NAME}"
else
    echo "[i] dpkg-deb not present on host. Staging prepared at ${DEB_STAGING}."
fi

echo "[4/4] Preparing RPM Package Staging (.rpm)..."
RPM_SPEC="${SCRIPT_DIR}/rpms/provigil-agent.spec"
if command -v rpmbuild > /dev/null 2>&1; then
    RPM_TOPDIR="${OUTPUT_DIR}/rpmbuild"
    mkdir -p "${RPM_TOPDIR}/"{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    cp "${BINARY}" "${RPM_TOPDIR}/SOURCES/siem-agent-linux"
    cp "${CRATE_DIR}/init/provigil-agent.service" "${RPM_TOPDIR}/SOURCES/provigil-agent.service"
    rpmbuild --define "_topdir ${RPM_TOPDIR}" -bb "${RPM_SPEC}"
    cp "${RPM_TOPDIR}"/RPMS/*/*.rpm "${OUTPUT_DIR}/" || true
    echo "[+] RPM package built in ${OUTPUT_DIR}/"
else
    echo "[i] rpmbuild tool not present on host. RPM SPEC and scripts ready at ${SCRIPT_DIR}/rpms."
fi

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
