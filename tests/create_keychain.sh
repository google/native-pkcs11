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

NATIVE_PKCS11_TMPDIR=$(mktemp -d -p "${RUNNER_TEMP:-}") || return 1
export NATIVE_PKCS11_TMPDIR
export NATIVE_PKCS11_KEYCHAIN_PATH="$NATIVE_PKCS11_TMPDIR/Test.keychain"
security create-keychain -p '' "$NATIVE_PKCS11_KEYCHAIN_PATH"
