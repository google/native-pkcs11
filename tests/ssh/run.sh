#!/bin/bash
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

set -ex

# https://stackoverflow.com/questions/59895/how-do-i-get-the-directory-where-a-bash-script-is-located-from-within-the-script
cd $(dirname -- "$( readlink -f -- "$0"; )")

security delete-keychain nativepkcs11test || true
security create-keychain -p "" nativepkcs11test
export NATIVE_PKCS11_KEYCHAIN_PATH=$HOME/Library/Keychains/nativepkcs11test-db

cargo run --bin create_selfsigned
security set-key-partition-list -S apple-tool:,apple: -s -k "" $NATIVE_PKCS11_KEYCHAIN_PATH

../../package-lipo.sh

cat sshd_config.template | envsubst > sshd_config
chmod 0600 ssh_host_ecdsa_key

NATIVE_PKCS11_LOG_STDERR=1 RUST_LOG=debug /usr/bin/ssh-keygen -D $PWD/../../target/libnative_pkcs11.dylib | grep -v pkcs11 > authorized_keys

($(which sshd) -D -e -f $PWD/sshd_config)&
SSHD_JOB=$!

sleep 1

SUCCESS=0
if NATIVE_PKCS11_LOG_STDERR=1 RUST_LOG=trace /usr/bin/ssh -vv -F ssh_config -o "PKCS11Provider=$PWD/../../target/libnative_pkcs11.dylib" test exit 0; then
  SUCCESS=1
fi

kill $SSHD_JOB

security delete-keychain nativepkcs11test || true

if [ "$SUCCESS" != 1 ]; then
  exit 1
fi

echo "SUCCESS" > /dev/stderr