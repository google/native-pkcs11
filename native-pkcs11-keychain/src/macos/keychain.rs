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
    item::{ItemSearchOptions, Location},
    os::macos::{item::ItemSearchOptionsExt, keychain::SecKeychain},
};

use crate::Result;

fn keychain() -> Result<Option<SecKeychain>> {
    match std::env::var("NATIVE_PKCS11_KEYCHAIN_PATH") {
        Ok(path) => Ok(Some(SecKeychain::open(path)?)),
        Err(_) => Ok(None),
    }
}

pub(crate) fn location() -> Result<Location> {
    match keychain()? {
        Some(keychain) => Ok(Location::FileKeychain(keychain)),
        None => Ok(Location::DefaultFileKeychain),
    }
}

pub fn item_search_options() -> Result<ItemSearchOptions> {
    let mut opts = ItemSearchOptions::new();
    if let Some(keychain) = keychain()? {
        opts.keychains(&[keychain]);
    }
    Ok(opts)
}
