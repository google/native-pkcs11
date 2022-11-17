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

use pkcs11::{
    attribute::{Attribute, AttributeType, Attributes},
    Result,
};
use pkcs11_sys::{
    CKO_CERTIFICATE,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKP_BASELINE_PROVIDER,
    CK_OBJECT_HANDLE,
};
use pkcs11_traits::{backend, KeySearchOptions};
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
    #[instrument]
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

    #[instrument]
    pub fn get(&self, handle: &CK_OBJECT_HANDLE) -> Option<&Object> {
        self.objects.get(handle)
    }

    #[instrument]
    pub fn find(&mut self, template: Attributes) -> Result<Vec<CK_OBJECT_HANDLE>> {
        let mut output = vec![];
        // Cache certificates.
        //
        // Firefox + NSS query certificates for every TLS connection in order to
        // evaluate server trust. Cache the results for 3 seconds.
        let should_reload = match self.last_loaded_certs {
            Some(last) => last.elapsed() >= std::time::Duration::from_secs(3),
            None => true,
        };
        if should_reload {
            for cert in backend().find_all_certificates()? {
                let private_key = backend().find_private_key(KeySearchOptions::PublicKeyHash(
                    cert.public_key().public_key_hash().as_slice().try_into()?,
                ))?;
                let private_key = match private_key {
                    Some(key) => key,
                    None => continue,
                };
                let cert = Object::Certificate(cert.into());
                self.insert(Object::PrivateKey(private_key));
                self.insert(cert);
            }
            self.last_loaded_certs = Some(std::time::Instant::now());
        }
        // All objects.
        // TODO(bweeks): search the keychain as well.
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
        // Search keychain.
        if output.is_empty() {
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
                CKO_PUBLIC_KEY | CKO_PRIVATE_KEY => {
                    let key_search_opts = if let Some(Attribute::Id(id)) =
                        template.get(AttributeType::Id)
                    {
                        KeySearchOptions::PublicKeyHash(id.as_slice().try_into()?)
                    } else if let Some(Attribute::Label(label)) = template.get(AttributeType::Label)
                    {
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
                                    output.push(self.insert(Object::PrivateKey(private_key)));
                                }
                                CKO_PUBLIC_KEY => {
                                    output.push(self.insert(Object::PublicKey(public_key.into())));
                                }
                                _ => {}
                            };
                        }
                        return Ok(output);
                    };
                    match *class {
                        CKO_PRIVATE_KEY => {
                            backend().find_private_key(key_search_opts)?.map(|key| {
                                output.push(self.insert(Object::PrivateKey(key)));
                            })
                        }
                        CKO_PUBLIC_KEY => backend().find_public_key(key_search_opts)?.map(|key| {
                            output.push(self.insert(Object::PublicKey(key.into())));
                        }),
                        _ => {
                            todo!();
                        }
                    };
                }
                _ => {
                    return Err(Error::AttributeTypeInvalid(*class));
                }
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

    use pkcs11_sys::CKO_PRIVATE_KEY;
    use pkcs11_traits::{backend, random_label};

    use super::*;

    #[test]
    fn test_object_store() {
        let label = &format!("objectstore test {}", random_label());

        let key = backend()
            .generate_key(pkcs11_traits::KeyAlgorithm::Rsa, Some(label))
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
}
