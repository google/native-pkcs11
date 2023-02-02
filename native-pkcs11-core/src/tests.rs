// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use native_pkcs11_traits::{backend, random_label, KeyAlgorithm};
use serial_test::serial;

use crate::*;

#[test]
#[serial]
fn key_alg() -> Result<()> {
    let ec = backend().generate_key(KeyAlgorithm::Ecc, Some(&random_label()))?;
    let rsa = backend().generate_key(KeyAlgorithm::Rsa, Some(&random_label()))?;

    assert_eq!(ec.algorithm(), KeyAlgorithm::Ecc);
    assert_eq!(rsa.algorithm(), KeyAlgorithm::Rsa);

    for key in [ec, rsa] {
        key.find_public_key(backend()).unwrap().unwrap().delete();
        key.delete();
    }

    Ok(())
}
