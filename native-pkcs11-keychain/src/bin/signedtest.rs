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

//! This binary must be codesigned since it uses the DataProtectionKeyhain.
#![allow(unused)]

#[cfg(target_os = "macos")]
mod macos {
    pub use native_pkcs11_keychain::certificate::{
        find_all_certificates,
        import_certificate,
        self_signed_certificate,
    };
    pub use native_pkcs11_traits::random_label;
    pub use security_framework::{
        item::{AddRef, ItemAddOptions, ItemClass, ItemSearchOptions, KeyClass},
        key::{GenerateKeyOptions, KeyType},
    };
}
#[cfg(target_os = "macos")]
fn main() -> Result<(), native_pkcs11_keychain::Error> {
    unpersisted_public_key()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn key_lifecycle() -> Result<(), native_pkcs11_keychain::Error> {
    use macos::*;
    use security_framework::item::{ItemAddValue, Location};
    let label = &random_label();

    let mut opts = GenerateKeyOptions::default();
    opts.set_key_type(KeyType::ec());
    opts.set_label(label);
    opts.set_token(security_framework::key::Token::SecureEnclave);
    opts.set_location(security_framework::item::Location::DataProtectionKeychain);

    let generated_key = security_framework::key::SecKey::new(&opts)?;

    if generated_key.external_representation().is_some() {
        Err("expected enclave key to not be exportable")?;
    }

    let generated_pubkey = generated_key
        .public_key()
        .ok_or("couldn't get public key")?
        .external_representation()
        .ok_or("couldn't get external representation of public key")?
        .to_vec();

    let results = native_pkcs11_keychain::keychain::item_search_options()?
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .search()?;
    if results.is_empty() {
        Err("expected to find key, but no keys found")?;
    }

    let found_key = match results.first().ok_or("no key found")? {
        security_framework::item::SearchResult::Ref(security_framework::item::Reference::Key(
            key,
        )) => key,
        _ => Err("expected ref result type")?,
    };

    let found_pubkey = found_key
        .public_key()
        .ok_or("couldn't get public key")?
        .external_representation()
        .ok_or("couldn't get external representation of public key")?
        .to_vec();

    if generated_pubkey != found_pubkey {
        Err("pubkeys not equal")?;
    }

    let test_payload = &random_label();
    let signature = generated_key.create_signature(
        security_framework_sys::key::Algorithm::ECDSASignatureMessageX962SHA256,
        test_payload.as_bytes(),
    )?;
    if !generated_key
        .public_key()
        .ok_or("no pubkey")?
        .verify_signature(
            security_framework_sys::key::Algorithm::ECDSASignatureMessageX962SHA256,
            test_payload.as_bytes(),
            &signature,
        )?
    {
        Err("signature verification failed")?;
    }

    let cert =
        self_signed_certificate(native_pkcs11_keychain::key::Algorithm::ECC, &generated_key)?;
    let cert = import_certificate(&cert)?;
    ItemAddOptions::new(ItemAddValue::Ref(AddRef::Certificate(cert.clone())))
        .set_location(Location::DataProtectionKeychain)
        .add()?;

    let certs = find_all_certificates()?;
    let mut found = false;
    for found_cert in certs {
        if found_cert.certificate()?.to_der() == cert.to_der() {
            found = true
        }
    }
    if !found {
        Err("didn't find matching cert")?;
    }

    cert.delete()?;
    generated_key.delete()?;

    Ok(())
}

//  This is adapted from key.rs for testing with the enclave. It appears keys
//  generated in the enclave always have a corresponding public SecKey
//  available.
#[cfg(target_os = "macos")]
fn unpersisted_public_key() -> Result<(), native_pkcs11_keychain::Error> {
    use macos::*;
    use native_pkcs11_keychain::KeychainBackend;
    use native_pkcs11_traits::Backend;
    use security_framework::{item::ItemAddValue, key::SecKey};
    let label = random_label();
    let key1 = SecKey::new(
        GenerateKeyOptions::default()
            .set_key_type(KeyType::ec())
            .set_label(&label)
            .set_token(security_framework::key::Token::SecureEnclave),
    )?;

    let pubkey_hash = key1.public_key().unwrap().application_label().unwrap();

    ItemAddOptions::new(ItemAddValue::Ref(AddRef::Key(key1)))
        .set_label(&label)
        .add()?;

    let found_key = KeychainBackend {}
        .find_private_key(native_pkcs11_traits::KeySearchOptions::Label(label))
        .map_err(|e| {
            dbg!(e);
            "find"
        })?
        .unwrap();

    assert_eq!(pubkey_hash, found_key.public_key_hash());

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {}
