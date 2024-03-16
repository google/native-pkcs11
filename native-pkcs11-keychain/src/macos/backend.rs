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

use apple_security_framework::{
    item::{KeyClass, Location},
    key::SecKey,
};
use apple_security_framework_sys::item::kSecAttrLabel;
use core_foundation::{
    base::{TCFType, ToVoid},
    string::CFString,
};
use native_pkcs11_traits::{Backend, Certificate, DataObject, SearchOptions};
use tracing::instrument;

use crate::{
    certificate::{find_all_certificates, import_identity, KeychainCertificate},
    key::{
        find_all_keys, find_certificate_using_application, find_certificate_using_label,
        find_key_using_application, find_key_using_label, generate_key, Algorithm,
        KeychainPrivateKey, KeychainPublicKey,
    },
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
    fn find_certificate(
        &self,
        query: SearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn Certificate>>> {
        let opt_key = match query {
            SearchOptions::Label(label) => find_certificate_using_label(&label)
                .ok()
                .map(|sec_cert| KeychainCertificate::new(import_identity(&sec_cert)?))
                .transpose()?,
            SearchOptions::Hash(certificate_hash) => {
                find_certificate_using_application(&certificate_hash)?
                    .map(|sec_cert| KeychainCertificate::new(import_identity(&sec_cert)?))
                    .transpose()?
            }
        };
        Ok(opt_key.map(|sec_cert| Arc::new(sec_cert) as _))
    }

    #[instrument]
    fn find_all_certificates(&self) -> native_pkcs11_traits::Result<Vec<Box<dyn Certificate>>> {
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
        query: SearchOptions,
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
            SearchOptions::Label(label) => find_key_using_label(KeyClass::private(), &label)
                .ok()
                .map(|sec_key| {
                    let cert = find_pubkey_for_seckey(&sec_key);
                    KeychainPrivateKey::new(sec_key, label, cert)
                })
                .transpose()?,
            SearchOptions::Hash(public_key_hash) => {
                find_key_using_application(KeyClass::private(), &public_key_hash)?
                    .map(|sec_key| {
                        let cert = find_pubkey_for_seckey(&sec_key);
                        KeychainPrivateKey::new(sec_key, "", cert)
                    })
                    .transpose()?
            }
        };
        Ok(opt_key.map(|sec_key| Arc::new(sec_key) as _))
    }

    #[instrument]
    fn find_public_key(
        &self,
        query: SearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn native_pkcs11_traits::PublicKey>>> {
        let opt_key = match query {
            SearchOptions::Label(label) => find_key_using_label(KeyClass::public(), &label)
                .ok()
                .map(|sec_key| KeychainPublicKey::new(sec_key, label))
                .transpose()?,
            SearchOptions::Hash(public_key_hash) => {
                find_key_using_application(KeyClass::public(), &public_key_hash)?
                    .map(|sec_key| KeychainPublicKey::new(sec_key, ""))
                    .transpose()?
            }
        };
        Ok(opt_key.map(|sec_key| Arc::new(sec_key) as _))
    }

    fn find_all_private_keys(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<Arc<dyn native_pkcs11_traits::PrivateKey>>> {
        let sec_keys = find_all_keys(KeyClass::private())?;
        let keys = sec_keys
            .into_iter()
            .filter_map(|sec_key| {
                let label: Option<String> = sec_key
                    .attributes()
                    .find(unsafe { kSecAttrLabel }.to_void())
                    .map(|label| {
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
                let label: Option<String> = sec_key
                    .attributes()
                    .find(unsafe { kSecAttrLabel }.to_void())
                    .map(|label| {
                        unsafe { CFString::wrap_under_get_rule(label.cast()) }.to_string()
                    });
                let label: String = label.unwrap_or_default();

                KeychainPublicKey::new(sec_key, label).ok()
            })
            .map(|k| Arc::new(k) as _);

        Ok(keys.collect())
    }

    fn find_data_object(
        &self,
        _query: SearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn DataObject>>> {
        Err("Finding data object is not not implemented for the Keychain Backend".into())
    }

    fn find_all_data_objects(&self) -> native_pkcs11_traits::Result<Vec<Arc<dyn DataObject>>> {
        Err("Finding all data object is not not implemented for the Keychain Backend".into())
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
        Ok(
            generate_key(alg, label, Some(Location::DefaultFileKeychain))
                .map(|key| KeychainPrivateKey::new(key, label, None).map(Arc::new))??,
        )
    }
}
