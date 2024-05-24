#!/bin/bash
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

set -exu

readonly CLIENT_CERT=/tmp/client.cer
readonly CLIENT_CSR=/tmp/client.csr
readonly CLIENT_KEY=/tmp/client.key
readonly CLIENT_P12_PASS='hunter2'
readonly CLIENT_P12=/tmp/client.p12
readonly CLIENT_ROOT_CERT=/tmp/client_root.cer
readonly CLIENT_ROOT_KEY=/tmp/client_root.key
readonly JAVA_ARGS='-Djava.security.debug=sunpkcs11,pkcs11keystore -Djavax.net.debug=ssl:handshake'
readonly NATIVE_PKCS11_KEYCHAIN_PATH=/tmp/nativepkcs11test.keychain
readonly PKCS11_CONFIG=/tmp/pkcs11.cfg
readonly RUST_LOG=trace
readonly SERVER_CERT=/tmp/server.cer
readonly SERVER_CSR=/tmp/server.csr
readonly SERVER_KEY=/tmp/server.key
readonly SERVER_KEY_P8=$SERVER_KEY.pk8
readonly SERVER_ROOT_CERT=/tmp/server_root.cer
readonly SERVER_ROOT_KEY=/tmp/server_root.key
readonly SUBJ='/C=US/ST=California/L=San Francisco/O=Google LLC'

export NATIVE_PKCS11_KEYCHAIN_PATH
export RUST_LOG

# https://stackoverflow.com/questions/59895/how-do-i-get-the-directory-where-a-bash-script-is-located-from-within-the-script
cd "$(dirname -- "$(readlink -f -- "$0")")"

# Server root
openssl ecparam -genkey -name prime256v1 -noout -out $SERVER_ROOT_KEY
openssl req -new -x509 -key $SERVER_ROOT_KEY -out $SERVER_ROOT_CERT \
    -subj "${SUBJ}/CN=Server Root"

# Server certificate
openssl ecparam -genkey -name prime256v1 -noout -out $SERVER_KEY
openssl req -new -key $SERVER_KEY -out $SERVER_CSR -subj "${SUBJ}/CN=localhost"
openssl pkcs8 -topk8 -nocrypt -in $SERVER_KEY -out "$SERVER_KEY_P8" -outform der
openssl x509 -req -CAkey $SERVER_ROOT_KEY -CA $SERVER_ROOT_CERT \
    -in $SERVER_CSR -out $SERVER_CERT -set_serial 1

# Client root
openssl ecparam -genkey -name prime256v1 -noout -out $CLIENT_ROOT_KEY
openssl req -new -x509 -key $CLIENT_ROOT_KEY -out $CLIENT_ROOT_CERT \
    -subj "${SUBJ}/CN=Client Root"

# Client certificate
openssl ecparam -genkey -name prime256v1 -noout -out $CLIENT_KEY
openssl req -new -key $CLIENT_KEY -out $CLIENT_CSR \
    -subj '/C=US/ST=California/L=San Francisco/O=Google LLC/CN=client'
openssl x509 -req -CAkey $CLIENT_ROOT_KEY -CA $CLIENT_ROOT_CERT \
    -in $CLIENT_CSR -out $CLIENT_CERT -set_serial 1
openssl pkcs12 -export -in $CLIENT_CERT -inkey $CLIENT_KEY \
    -certfile $CLIENT_ROOT_CERT -out $CLIENT_P12 -passout pass:$CLIENT_P12_PASS

security delete-keychain $NATIVE_PKCS11_KEYCHAIN_PATH || true
security create-keychain -p "" $NATIVE_PKCS11_KEYCHAIN_PATH
security import $CLIENT_P12 -k $NATIVE_PKCS11_KEYCHAIN_PATH -P \
    $CLIENT_P12_PASS -A
security set-key-partition-list -S teamid:TDTHCUPYFR -s -k "" \
    $NATIVE_PKCS11_KEYCHAIN_PATH

cat <<EOF >$PKCS11_CONFIG
name = native-pkcs11
library = $(realpath ../../target/debug/libnative_pkcs11.dylib)
EOF

java "$JAVA_ARGS" SunPKCS11ProviderTest.java $PKCS11_CONFIG "$SERVER_KEY_P8" \
    $SERVER_CERT $SERVER_ROOT_CERT $CLIENT_ROOT_CERT
