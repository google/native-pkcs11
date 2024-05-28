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

readonly CLIENT_P12_PASS='hunter2'
readonly SUBJ='/C=US/ST=California/L=San Francisco/O=Google LLC'

readonly CLIENT_CERT=$NATIVE_PKCS11_TMPDIR/client.cer
readonly CLIENT_CSR=$NATIVE_PKCS11_TMPDIR/client.csr
readonly CLIENT_KEY=$NATIVE_PKCS11_TMPDIR/client.key
readonly CLIENT_P12=$NATIVE_PKCS11_TMPDIR/client.p12
readonly CLIENT_ROOT_CERT=$NATIVE_PKCS11_TMPDIR/client_root.cer
readonly CLIENT_ROOT_KEY=$NATIVE_PKCS11_TMPDIR/client_root.key
readonly SERVER_CERT=$NATIVE_PKCS11_TMPDIR/server.cer
readonly SERVER_CSR=$NATIVE_PKCS11_TMPDIR/server.csr
readonly SERVER_KEY=$NATIVE_PKCS11_TMPDIR/server.key
readonly SERVER_KEY_P8=$SERVER_KEY.pk8
readonly SERVER_ROOT_CERT=$NATIVE_PKCS11_TMPDIR/server_root.cer
readonly SERVER_ROOT_KEY=$NATIVE_PKCS11_TMPDIR/server_root.key

# Avoid using OpenSSL from Homebrew, which differs substantially from LibreSSL.
shopt -s expand_aliases
alias openssl=/usr/bin/openssl

# Server root
openssl ecparam -genkey -name prime256v1 -noout -out "$SERVER_ROOT_KEY"
openssl req -new -x509 -key "$SERVER_ROOT_KEY" -out "$SERVER_ROOT_CERT" \
  -subj "${SUBJ}/CN=Server Root"

# Server certificate
openssl ecparam -genkey -name prime256v1 -noout -out "$SERVER_KEY"
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
  -subj "${SUBJ}/CN=localhost"
openssl pkcs8 -topk8 -nocrypt -in "$SERVER_KEY" -out "$SERVER_KEY_P8" \
  -outform der
openssl x509 -req -CAkey "$SERVER_ROOT_KEY" -CA "$SERVER_ROOT_CERT" \
  -in "$SERVER_CSR" -out "$SERVER_CERT" -set_serial 1

# Client root
openssl ecparam -genkey -name prime256v1 -noout -out "$CLIENT_ROOT_KEY"
openssl req -new -x509 -key "$CLIENT_ROOT_KEY" -out "$CLIENT_ROOT_CERT" \
  -subj "${SUBJ}/CN=Client Root"

# Client certificate
if [ -n "${QUIRK_RSA_CLIENT_KEY:-}" ]; then
  openssl genrsa -out "$CLIENT_KEY" 2048
else
  openssl ecparam -genkey -name prime256v1 -noout -out "$CLIENT_KEY"
fi
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" \
  -subj '/C=US/ST=California/L=San Francisco/O=Google LLC/CN=localhost'
openssl x509 -req -CAkey "$CLIENT_ROOT_KEY" -CA "$CLIENT_ROOT_CERT" \
  -in "$CLIENT_CSR" -out "$CLIENT_CERT" -set_serial 1
openssl pkcs12 -export -in "$CLIENT_CERT" -inkey "$CLIENT_KEY" \
  -certfile "$CLIENT_ROOT_CERT" -out "$CLIENT_P12" -passout pass:$CLIENT_P12_PASS

security import "$CLIENT_P12" -k "$NATIVE_PKCS11_KEYCHAIN_PATH" -P \
  $CLIENT_P12_PASS -A
