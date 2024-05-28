#!/bin/bash
# shellcheck source-path=SCRIPTDIR
#
# Copyright 2022 Google LLC
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

# MACOS ONLY

set -eux

# https://stackoverflow.com/questions/59895/how-do-i-get-the-directory-where-a-bash-script-is-located-from-within-the-script
cd "$(dirname -- "$(readlink -f -- "$0")")"

. ../create_keychain.sh
# TODO(bweeks): ssh integration test breaks with a P-256 client key.
export QUIRK_RSA_CLIENT_KEY=1
. ../create_selfsigned.sh

../../package-lipo.sh

export AUTHORIZED_KEYS=$NATIVE_PKCS11_TMPDIR/authorized_keys
NATIVE_PKCS11_LOG_STDERR=1 RUST_LOG=debug /usr/bin/ssh-keygen -D \
  "$PWD/../../target/libnative_pkcs11.dylib" | grep -v pkcs11 >"$AUTHORIZED_KEYS"

readonly SSHD_CONFIG=$NATIVE_PKCS11_TMPDIR/sshd_config
envsubst <sshd_config.template >"$SSHD_CONFIG"
chmod 0600 ssh_host_ecdsa_key

($(which sshd) -D -e -f "$SSHD_CONFIG") &
SSHD_JOB=$!

sleep 1

SUCCESS=0
if NATIVE_PKCS11_LOG_STDERR=1 RUST_LOG=trace /usr/bin/ssh -vv -F ssh_config \
  -o "PKCS11Provider=$PWD/../../target/libnative_pkcs11.dylib" test exit 0; then
  SUCCESS=1
fi

kill $SSHD_JOB

if [ "$SUCCESS" != 1 ]; then
  exit 1
fi

echo "SUCCESS" >/dev/stderr
