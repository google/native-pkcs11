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

use cached::{Cached, TimedCache};
use native_pkcs11_core::{
    Result,
    attribute::{Attribute, AttributeType, Attributes},
};
use native_pkcs11_traits::{KeySearchOptions, backend};
use pkcs11_sys::{
    CK_OBJECT_HANDLE,
    CKO_CERTIFICATE,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKP_BASELINE_PROVIDER,
};
use tracing::{instrument, warn};

use crate::{Error, object::Object};

#[derive(Debug)]
pub struct ObjectStore {
    objects: HashMap<CK_OBJECT_HANDLE, Object>,
    handles_by_object: HashMap<Object, CK_OBJECT_HANDLE>,
    next_object_handle: CK_OBJECT_HANDLE,
    query_cache: TimedCache<Attributes, Vec<CK_OBJECT_HANDLE>>,
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
        if let Some(c) = self.query_cache.cache_get(&template) {
            Ok(c.to_vec())
        } else {
            let output = self.find_impl(&template)?;
            self.query_cache.cache_set(template, output.clone());
            Ok(output)
        }
    }

    #[instrument(skip(self))]
    fn find_impl(&mut self, template: &Attributes) -> Result<Vec<CK_OBJECT_HANDLE>> {
        self.find_with_backend(template)?;
        if template.is_empty() { Ok(self.find_all()) } else { Ok(self.find_store(template)) }
    }

    #[instrument(skip(self))]
    fn find_all(&self) -> Vec<CK_OBJECT_HANDLE> {
        self.objects.keys().copied().collect()
    }

    #[instrument(skip(self))]
    fn find_store(&self, template: &Attributes) -> Vec<CK_OBJECT_HANDLE> {
        self.objects
            .iter()
            .filter(|(_, object)| object.matches(template))
            .map(|(handle, _)| *handle)
            .collect()
    }

    #[instrument(skip(self))]
    fn find_with_backend(&mut self, template: &Attributes) -> Result<()> {
        if template.is_empty() {
            self.find_with_backend_all_certificates()?;
            self.find_with_backend_all_public_keys()?;
            self.find_with_backend_all_private_keys()?;
            return Ok(());
        }

        let class = match template.get(AttributeType::Class) {
            Some(Attribute::Class(class)) => class,
            None => {
                return Err(Error::Todo("no class attribute".to_string()));
            }
            class => {
                return Err(Error::Todo(format!("class {class:?} not implemented")));
            }
        };
        match *class {
            CKO_CERTIFICATE => {
                if template.len() > 1 {
                    warn!("ignoring attributes for certificate search");
                }
                self.find_with_backend_all_certificates()?;
            }
            // CKO_NSS_TRUST | CKO_NETSCAPE_BUILTIN_ROOT_LIST
            3461563219 | 3461563220 => (),
            CKO_SECRET_KEY => (),
            CKO_PUBLIC_KEY | CKO_PRIVATE_KEY => {
                let opts = if let Some(Attribute::Id(id)) = template.get(AttributeType::Id) {
                    KeySearchOptions::Id(id.clone())
                } else if let Some(Attribute::Label(label)) = template.get(AttributeType::Label) {
                    KeySearchOptions::Label(label.into())
                } else {
                    match *class {
                        CKO_PRIVATE_KEY => self.find_with_backend_all_private_keys()?,
                        CKO_PUBLIC_KEY => self.find_with_backend_all_public_keys()?,
                        _ => unreachable!(),
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

    fn find_with_backend_all_certificates(&mut self) -> Result<()> {
        for cert in backend().find_all_certificates()? {
            self.insert(Object::Certificate(cert.into()));
        }
        Ok(())
    }

    fn find_with_backend_all_public_keys(&mut self) -> Result<()> {
        for public_key in backend().find_all_public_keys()? {
            self.insert(Object::PublicKey(public_key));
        }
        Ok(())
    }

    fn find_with_backend_all_private_keys(&mut self) -> Result<()> {
        for private_key in backend().find_all_private_keys()? {
            self.insert(Object::PrivateKey(private_key));
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
            query_cache: TimedCache::with_lifespan(10),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use native_pkcs11_traits::{KeyAlgorithm, backend, random_label};
    use pkcs11_sys::CKO_PRIVATE_KEY;
    use serial_test::serial;

    use super::*;
    use crate::tests::test_init;

    #[test]
    #[serial]
    fn test_object_store() {
        test_init();

        let label = &format!("objectstore test {}", random_label());

        let key =
            backend().generate_key(native_pkcs11_traits::KeyAlgorithm::Rsa, Some(label)).unwrap();

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
