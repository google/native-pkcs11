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

use std::{collections::HashMap, sync::Arc};

use core_foundation::{
    base::{TCFType, ToVoid},
    string::CFString,
};
use native_pkcs11_traits::Backend;
use security_framework::{item::KeyClass, key::SecKey};
use security_framework_sys::item::kSecAttrLabel;
use tracing::instrument;

use crate::{
    certificate::{KeychainCertificate, find_all_certificates},
    key::{
        Algorithm,
        KeychainPrivateKey,
        KeychainPublicKey,
        find_all_keys,
        find_key,
        find_key2,
        generate_key,
    },
    keychain,
};

#[derive(Debug, Default)]
pub struct KeychainBackend;

impl KeychainBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Backend for KeychainBackend {
    fn name(&self) -> String {
        "Keychain".into()
    }

    #[instrument]
    fn find_all_certificates(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<Box<dyn native_pkcs11_traits::Certificate>>> {
        let certs = find_all_certificates()?
            .into_iter()
            .map(KeychainCertificate::new)
            .filter_map(Result::ok)
            .map(|cert| Box::new(cert) as _)
            .collect();
        Ok(certs)
    }

    #[instrument]
    fn find_private_key(
        &self,
        query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn native_pkcs11_traits::PrivateKey>>> {
        let mut pubkeys_by_pubkey_hash: HashMap<Vec<u8>, SecKey> =
            HashMap::from_iter(find_all_certificates()?.into_iter().filter_map(|c| {
                c.certificate()
                    .ok()
                    .and_then(|cert| cert.public_key().ok())
                    .and_then(|pk| pk.application_label().map(|pubkey_hash| (pubkey_hash, pk)))
            }));

        let mut find_pubkey_for_seckey = |sec_key: &SecKey| -> Option<KeychainPublicKey> {
            sec_key
                .application_label()
                .and_then(|pubkey_hash| pubkeys_by_pubkey_hash.remove(&pubkey_hash))
                //  TODO(kcking): populate label if searching by label
                .and_then(|sec_key| KeychainPublicKey::new(sec_key, "").ok())
        };
        let opt_key = match query {
            native_pkcs11_traits::KeySearchOptions::Id(id) => find_key2(KeyClass::private(), &id)?
                .map(|sec_key| {
                    let cert = find_pubkey_for_seckey(&sec_key);
                    KeychainPrivateKey::new(sec_key, "", cert)
                })
                .transpose()?,
            native_pkcs11_traits::KeySearchOptions::Label(label) => {
                find_key(KeyClass::private(), &label)
                    .ok()
                    .map(|sec_key| {
                        let cert = find_pubkey_for_seckey(&sec_key);
                        KeychainPrivateKey::new(sec_key, label, cert)
                    })
                    .transpose()?
            }
        };
        Ok(opt_key.map(|sec_key| Arc::new(sec_key) as _))
    }

    #[instrument]
    fn find_public_key(
        &self,
        query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Box<dyn native_pkcs11_traits::PublicKey>>> {
        let opt_key = match query {
            native_pkcs11_traits::KeySearchOptions::Id(id) => find_key2(KeyClass::public(), &id)?
                .map(|sec_key| KeychainPublicKey::new(sec_key, ""))
                .transpose()?,
            native_pkcs11_traits::KeySearchOptions::Label(label) => {
                find_key(KeyClass::public(), &label)
                    .ok()
                    .map(|sec_key| KeychainPublicKey::new(sec_key, label))
                    .transpose()?
            }
        };
        Ok(opt_key.map(|sec_key| Box::new(sec_key) as _))
    }

    #[instrument]
    fn generate_key(
        &self,
        algorithm: native_pkcs11_traits::KeyAlgorithm,
        label: Option<&str>,
    ) -> native_pkcs11_traits::Result<Arc<dyn native_pkcs11_traits::PrivateKey>> {
        let alg = match algorithm {
            native_pkcs11_traits::KeyAlgorithm::Rsa => Algorithm::RSA,
            native_pkcs11_traits::KeyAlgorithm::Ecc => Algorithm::ECC,
        };
        let label = label.unwrap_or("");
        Ok(generate_key(alg, label, keychain::location()?)
            .map(|key| KeychainPrivateKey::new(key, label, None).map(Arc::new))??)
    }

    fn find_all_private_keys(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<Arc<dyn native_pkcs11_traits::PrivateKey>>> {
        let sec_keys = find_all_keys(KeyClass::private())?;
        let keys = sec_keys
            .into_iter()
            .filter_map(|sec_key| {
                let label: Option<String> =
                    sec_key.attributes().find(unsafe { kSecAttrLabel }.to_void()).map(|label| {
                        unsafe { CFString::wrap_under_get_rule(label.cast()) }.to_string()
                    });
                let label: String = label.unwrap_or_default();

                KeychainPrivateKey::new(sec_key, label, None).ok()
            })
            .map(|k| Arc::new(k) as _);

        Ok(keys.collect())
    }

    fn find_all_public_keys(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<Arc<dyn native_pkcs11_traits::PublicKey>>> {
        let sec_keys = find_all_keys(KeyClass::public())?;

        let keys = sec_keys
            .into_iter()
            .filter_map(|sec_key| {
                let label: Option<String> =
                    sec_key.attributes().find(unsafe { kSecAttrLabel }.to_void()).map(|label| {
                        unsafe { CFString::wrap_under_get_rule(label.cast()) }.to_string()
                    });
                let label: String = label.unwrap_or_default();

                KeychainPublicKey::new(sec_key, label).ok()
            })
            .map(|k| Arc::new(k) as _);

        Ok(keys.collect())
    }
}
