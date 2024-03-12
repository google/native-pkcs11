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

use std::collections::{HashMap, HashSet};

use native_pkcs11_core::{
    attribute::{Attribute, AttributeType, Attributes},
    compoundid,
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
    // TODO: `objects` and `handles_by_object` could be replaced by a `bimap`
    // (Bijective Map) data structure.
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

    // Removes objects from handle store that are not part of `objects`.
    // Allocates new handles for objects in `objects` that are newly stored.
    fn set_objects(&mut self, objects: Vec<Object>) {
        let objects: HashSet<Object> = HashSet::from_iter(objects);
        let to_remove: Vec<_> = self
            .handles_by_object
            .iter()
            .filter(|entry| !objects.contains(entry.0))
            .map(|entry| (entry.0.clone(), *entry.1))
            .collect();
        to_remove.into_iter().for_each(|(obj, handle)| {
            self.objects.remove(&handle);
            self.handles_by_object.remove(&obj);
        });

        objects.into_iter().for_each(|object| {
            self.insert(object);
        });
    }

    #[instrument(skip(self))]
    pub fn get(&self, handle: &CK_OBJECT_HANDLE) -> Option<&Object> {
        self.objects.get(handle)
    }

    #[instrument(skip(self))]
    fn reload_if_needed(&mut self) -> Result<()> {
        // Cache certificates.
        //
        // Firefox + NSS query certificates for every TLS connection in order to
        // evaluate server trust. Cache the results for 3 seconds.
        //
        // TODO: consider a "burstable" cache timeout, ie. up to N queries per
        // M-second window, so that new objects are more likely to be
        // immediately discovered.
        let should_reload = match self.last_loaded_certs {
            Some(last) => last.elapsed() >= std::time::Duration::from_secs(3),
            None => true,
        };
        if should_reload {
            let mut objects = vec![];
            for cert in backend().find_all_certificates()? {
                let private_key = backend().find_private_key(KeySearchOptions::PublicKeyHash(
                    cert.public_key().public_key_hash().as_slice().try_into()?,
                ))?;
                //  Check if certificate has an associated PrivateKey.
                match private_key {
                    Some(key) => key,
                    None => continue,
                };
                objects.push(Object::Certificate(cert.into()));
            }
            //  Add all keys, regardless of label.
            for private_key in backend().find_all_private_keys()? {
                objects.push(Object::PrivateKey(private_key));
            }
            for public_key in backend().find_all_public_keys()? {
                objects.push(Object::PublicKey(public_key));
            }

            // Use `self.set_objects` here to ensure objects that no longer
            // exist are cleared from the ObjectStore.
            self.set_objects(objects);
            self.last_loaded_certs = Some(std::time::Instant::now());
        }
        Ok(())
    }

    #[instrument(skip(self))]
    pub fn find(&mut self, template: Attributes) -> Result<Vec<CK_OBJECT_HANDLE>> {
        self.reload_if_needed()?;

        let mut output = vec![];
        // All objects.
        if template.is_empty() {
            for handle in self.objects.keys() {
                output.push(*handle);
            }
            return Ok(output);
        }
        // Search the object store.
        for (handle, object) in self.objects.iter() {
            if object.matches(&template) {
                output.push(*handle);
            }
        }
        Ok(output)
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
