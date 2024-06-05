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

use std::collections::HashMap;

use native_pkcs11_core::{
    attribute::{Attribute, AttributeType, Attributes},
    Result,
};
use native_pkcs11_traits::{backend, KeySearchOptions};
use pkcs11_sys::{
    CKO_CERTIFICATE,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKP_BASELINE_PROVIDER,
    CK_OBJECT_HANDLE,
};
use tracing::{instrument, warn};

use crate::{object::Object, Error};

#[derive(Debug)]
pub struct ObjectStore {
    objects: HashMap<CK_OBJECT_HANDLE, Object>,
    handles_by_object: HashMap<Object, CK_OBJECT_HANDLE>,
    next_object_handle: CK_OBJECT_HANDLE,
    last_loaded_certs: Option<std::time::Instant>,
}

impl ObjectStore {
    #[instrument(skip(self))]
    pub fn insert(&mut self, object: Object) -> CK_OBJECT_HANDLE {
        if let Some(existing_handle) = self.handles_by_object.get(&object) {
            return *existing_handle;
        }
        let handle = self.next_object_handle + 1;
        self.next_object_handle += 1;
        self.objects.insert(handle, object.clone());
        self.handles_by_object.insert(object, handle);
        handle
    }

    #[instrument(skip(self))]
    pub fn get(&self, handle: &CK_OBJECT_HANDLE) -> Option<&Object> {
        self.objects.get(handle)
    }

    #[instrument(skip(self))]
    pub fn find(&mut self, template: Attributes) -> Result<Vec<CK_OBJECT_HANDLE>> {
        // Cache certificates.
        //
        // Firefox + NSS query certificates for every TLS connection in order to
        // evaluate server trust. Cache the results for 3 seconds.
        self.load_cache()?;

        // If the template is empty, return all objects in the store.
        // TODO(bweeks): search the backend as well.
        if template.is_empty() {
            return Ok(self.find_all());
        }

        // Search the store for objects matching the template.
        let output = self.find_store(&template);
        if output.is_empty() {
            // No objects found, load objects from the backend and try search again.
            self.find_backend(&template)?;
            Ok(self.find_store(&template))
        } else {
            Ok(output)
        }
    }

    fn load_cache(&mut self) -> Result<()> {
        if let Some(last) = self.last_loaded_certs {
            if last.elapsed() < std::time::Duration::from_secs(3) {
                return Ok(());
            }
        }

        for cert in backend().find_all_certificates()? {
            let private_key = backend().find_private_key(KeySearchOptions::PublicKeyHash(
                cert.public_key().public_key_hash().as_slice().try_into()?,
            ))?;
            //  Check if certificate has an associated PrivateKey.
            match private_key {
                Some(key) => key,
                None => continue,
            };
            self.insert(Object::Certificate(cert.into()));
        }
        //  Add all keys, regardless of label.
        for private_key in backend().find_all_private_keys()? {
            self.insert(Object::PrivateKey(private_key));
        }
        for public_key in backend().find_all_public_keys()? {
            self.insert(Object::PublicKey(public_key));
        }
        self.last_loaded_certs = Some(std::time::Instant::now());
        Ok(())
    }

    fn find_all(&self) -> Vec<CK_OBJECT_HANDLE> {
        self.objects.keys().copied().collect()
    }

    fn find_store(&self, template: &Attributes) -> Vec<CK_OBJECT_HANDLE> {
        self.objects
            .iter()
            .filter(|(_, object)| object.matches(template))
            .map(|(handle, _)| *handle)
            .collect()
    }

    fn find_backend(&mut self, template: &Attributes) -> Result<()> {
        let class = match template.get(AttributeType::Class) {
            Some(Attribute::Class(class)) => class,
            None => {
                return Err(Error::Todo("no class attribute".to_string()));
            }
            class => {
                todo!("class not implemented: {:?}", class);
            }
        };
        match *class {
            CKO_CERTIFICATE => (),
            // CKO_NSS_TRUST | CKO_NETSCAPE_BUILTIN_ROOT_LIST
            3461563219 | 3461563220 => (),
            CKO_SECRET_KEY => (),
            CKO_PUBLIC_KEY | CKO_PRIVATE_KEY => {
                let opts = if let Some(Attribute::Id(id)) = template.get(AttributeType::Id) {
                    KeySearchOptions::PublicKeyHash(id.as_slice().try_into()?)
                } else if let Some(Attribute::Label(label)) = template.get(AttributeType::Label) {
                    KeySearchOptions::Label(label.into())
                } else {
                    for private_key in backend().find_all_private_keys()? {
                        //  Only consider keys that have both private and public parts present.
                        let public_key = match private_key.find_public_key(backend()) {
                            Ok(Some(public_key)) => public_key,
                            _ => continue,
                        };
                        match *class {
                            CKO_PRIVATE_KEY => {
                                self.insert(Object::PrivateKey(private_key));
                            }
                            CKO_PUBLIC_KEY => {
                                self.insert(Object::PublicKey(public_key.into()));
                            }
                            _ => unreachable!(),
                        };
                    }
                    return Ok(());
                };
                match *class {
                    CKO_PRIVATE_KEY => backend().find_private_key(opts)?.map(|key| {
                        self.insert(Object::PrivateKey(key));
                    }),
                    CKO_PUBLIC_KEY => backend().find_public_key(opts)?.map(|key| {
                        self.insert(Object::PublicKey(key.into()));
                    }),
                    _ => unreachable!(),
                };
            }
            _ => {
                return Err(Error::AttributeTypeInvalid(*class));
            }
        }
        Ok(())
    }
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self {
            objects: HashMap::from([(1, Object::Profile(CKP_BASELINE_PROVIDER))]),
            handles_by_object: HashMap::from([(Object::Profile(CKP_BASELINE_PROVIDER), 1)]),
            next_object_handle: 2,
            last_loaded_certs: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use native_pkcs11_traits::{backend, random_label, KeyAlgorithm};
    use pkcs11_sys::CKO_PRIVATE_KEY;
    use serial_test::serial;

    use super::*;
    use crate::tests::test_init;

    #[test]
    #[serial]
    fn test_object_store() {
        test_init();

        let label = &format!("objectstore test {}", random_label());

        let key = backend()
            .generate_key(native_pkcs11_traits::KeyAlgorithm::Rsa, Some(label))
            .unwrap();

        let mut store = ObjectStore::default();

        let template = Attributes::from(vec![
            Attribute::Class(CKO_PRIVATE_KEY),
            Attribute::Label(label.into()),
        ]);
        let private_key_handle = store.find(template.clone()).unwrap()[0];
        //  find again
        assert_eq!(store.find(template).unwrap()[0], private_key_handle);

        key.find_public_key(backend()).unwrap().unwrap().delete();
        key.delete();
    }

    #[test]
    #[serial]
    fn key_alg() -> Result<()> {
        test_init();
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
}
