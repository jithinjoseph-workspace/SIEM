#!/bin/bash
# For each unresolved symbol in build.log, the C files that define it.
cd ~/wazuh-mon-src/src
for s in $(grep -oE "undefined reference to \`[A-Za-z_0-9]+" ~/mail_oracle/build.log | sed 's/.*`//' | sort -u); do
  f=$(grep -lE "^[A-Za-z_].*[ *]$s *(\(|\[| =)" shared/*.c config/*.c wazuh_db/*.c wazuh_db/helpers/*.c os_*/*.c 2>/dev/null | grep -v test | head -3 | tr '\n' ' ')
  echo "$s: $f"
done
