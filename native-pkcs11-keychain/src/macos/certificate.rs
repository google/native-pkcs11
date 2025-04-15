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

use security_framework::{
    identity::SecIdentity,
    item::{ItemClass, Reference},
};
use security_framework_sys::base::errSecItemNotFound;

use crate::{Result, key::KeychainPublicKey};

pub(crate) struct KeychainCertificate {
    pub label: String,
    pub identity: SecIdentity,
    pub public_key: KeychainPublicKey,
    certificate_der: Vec<u8>,
}

impl KeychainCertificate {
    pub fn new(identity: impl Into<SecIdentity>) -> Result<Self> {
        let identity: SecIdentity = identity.into();
        let label = identity.certificate().unwrap().subject_summary();
        let pk = identity.certificate()?.public_key()?;
        Ok(Self {
            certificate_der: identity.certificate()?.to_der(),
            label: label.clone(),
            identity,
            public_key: KeychainPublicKey::new(pk, label)?,
        })
    }
}

impl std::fmt::Debug for KeychainCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeychainCertificate")
            .field("label", &self.label)
            .field("identity", &self.identity)
            .finish()
    }
}

impl native_pkcs11_traits::Certificate for KeychainCertificate {
    fn id(&self) -> Vec<u8> {
        self.public_key().id()
    }

    fn label(&self) -> String {
        self.label.to_string()
    }

    fn public_key(&self) -> &dyn native_pkcs11_traits::PublicKey {
        &self.public_key
    }

    fn to_der(&self) -> Vec<u8> {
        self.certificate_der.clone()
    }

    fn delete(self: Box<Self>) {
        let _ = self.identity.delete();
    }
}

pub fn find_all_certificates() -> Result<Vec<SecIdentity>> {
    let results = crate::macos::keychain::item_search_options()?
        .load_refs(true)
        .class(ItemClass::identity())
        .limit(99)
        .search();

    if let Err(e) = results {
        if e.code() == errSecItemNotFound {
            return Ok(vec![]);
        }
    }

    let loaded_identites = results?
        .into_iter()
        .filter_map(|result| match result {
            security_framework::item::SearchResult::Ref(Reference::Identity(identity)) => {
                Some(identity)
            }
            _ => None,
        })
        .collect();

    Ok(loaded_identites)
}
