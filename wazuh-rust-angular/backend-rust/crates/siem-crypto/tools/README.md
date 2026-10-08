# msgs.c oracle

`msgs_harness.c` drives Wazuh's real `src/os_crypto/shared/msgs.c`,
`aes_op.c` and `bf_op.c` (unmodified) with the stub headers in `shim/`.
It links directly against an OpenSSL 3 `libcrypto` and `zlib` shared library.

Build it (Windows, Git-for-Windows OpenSSL/zlib DLLs + llvm-mingw):

    W=<wazuh-4.14.7>/src
    gcc -O1 -w -Ishim -I$W -o msgs_harness msgs_harness.c \
        $W/os_crypto/shared/msgs.c $W/os_crypto/aes/aes_op.c $W/os_crypto/blowfish/bf_op.c \
        /mingw64/bin/libcrypto-3-x64.dll /mingw64/bin/zlib1.dll -lpthread

On Linux, link with `-lcrypto -lz` instead.

Run the differential test (from the workspace root):

    SIEM_MSGS_ORACLE=/path/to/msgs_harness cargo test -p siem-crypto --test msgs_oracle -- --nocapture

The harness creates `rids/` in its working directory.
