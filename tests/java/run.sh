#!/bin/bash
# shellcheck source-path=SCRIPTDIR
#
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eux

# https://stackoverflow.com/questions/59895/how-do-i-get-the-directory-where-a-bash-script-is-located-from-within-the-script
cd "$(dirname -- "$(readlink -f -- "$0")")"

. ../create_keychain.sh
. ../create_selfsigned.sh
security set-key-partition-list -S teamid:TDTHCUPYFR -s -k "" \
  "$NATIVE_PKCS11_KEYCHAIN_PATH"

cargo build -p native-pkcs11

readonly PKCS11_CONFIG=$NATIVE_PKCS11_TMPDIR/pkcs11.cfg
cat <<EOF >"$PKCS11_CONFIG"
name = native-pkcs11
library = "$PWD/../../target/debug/libnative_pkcs11.dylib"
EOF

java \
  -Djava.security.debug=sunpkcs11,pkcs11keystore \
  -Djavax.net.debug=ssl:handshake \
  SunPKCS11ProviderTest.java "$PKCS11_CONFIG" \
  "$SERVER_KEY_P8" "$SERVER_CERT" "$SERVER_ROOT_CERT" "$CLIENT_ROOT_CERT"

echo "SUCCESS" >/dev/stderr
