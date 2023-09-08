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
    pub use apple_security_framework::{
        item::{add_item, AddRef, ItemAddOptions, ItemClass, ItemSearchOptions, KeyClass},
        key::{GenerateKeyOptions, KeyType},
    };
    pub use native_pkcs11_keychain::certificate::{
        find_all_certificates,
        import_certificate,
        self_signed_certificate,
    };
    pub use native_pkcs11_traits::random_label;
}
#[cfg(target_os = "macos")]
fn main() -> Result<(), native_pkcs11_keychain::Error> {
    unpersisted_public_key()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn key_lifecycle() -> Result<(), native_pkcs11_keychain::Error> {
    use macos::*;
    let label = &random_label();
    let args = GenerateKeyOptions::default()
        .set_key_type(KeyType::ec())
        .set_label(label)
        .set_token(apple_security_framework::key::Token::SecureEnclave)
        .set_location(apple_security_framework::item::Location::DataProtectionKeychain)
        .to_dictionary();

    let generated_key = apple_security_framework::key::SecKey::generate(args)?;

    if generated_key.external_representation().is_some() {
        return Err("expected enclave key to not be exportable")?;
    }

    let generated_pubkey = generated_key
        .public_key()
        .ok_or("couldn't get public key")?
        .external_representation()
        .ok_or("couldn't get external representation of public key")?
        .to_vec();

    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .search()?;
    if results.is_empty() {
        return Err("expected to find key, but no keys found")?;
    }

    let found_key = match results.get(0).ok_or("no key found")? {
        apple_security_framework::item::SearchResult::Ref(
            apple_security_framework::item::Reference::Key(key),
        ) => key,
        _ => Err("expected ref result type")?,
    };

    let found_pubkey = found_key
        .public_key()
        .ok_or("couldn't get public key")?
        .external_representation()
        .ok_or("couldn't get external representation of public key")?
        .to_vec();

    if generated_pubkey != found_pubkey {
        return Err("pubkeys not equal")?;
    }

    let test_payload = &random_label();
    let signature = generated_key.create_signature(
        apple_security_framework_sys::key::Algorithm::ECDSASignatureMessageX962SHA256,
        test_payload.as_bytes(),
    )?;
    if !generated_key
        .public_key()
        .ok_or("no pubkey")?
        .verify_signature(
            apple_security_framework_sys::key::Algorithm::ECDSASignatureMessageX962SHA256,
            test_payload.as_bytes(),
            &signature,
        )?
    {
        return Err("signature verification failed")?;
    }

    let cert =
        self_signed_certificate(native_pkcs11_keychain::key::Algorithm::ECC, &generated_key)?;
    let cert = import_certificate(&cert)?;
    let add_params = ItemAddOptions::new(apple_security_framework::item::ItemAddValue::Ref(
        AddRef::Certificate(cert.clone()),
    ))
    .set_location(apple_security_framework::item::Location::DataProtectionKeychain)
    .to_dictionary();
    add_item(add_params)?;

    let certs = find_all_certificates()?;
    let mut found = false;
    for found_cert in certs {
        if found_cert.certificate()?.to_der() == cert.to_der() {
            found = true
        }
    }
    if !found {
        return Err("didn't find matching cert")?;
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
    use apple_security_framework::key::SecKey;
    use macos::*;
    use native_pkcs11_keychain::KeychainBackend;
    use native_pkcs11_traits::Backend;
    let label = random_label();
    let key1 = SecKey::generate(
        GenerateKeyOptions::default()
            .set_key_type(KeyType::ec())
            .set_label(&label)
            .set_token(apple_security_framework::key::Token::SecureEnclave)
            //  NOTE: Purposefully not storing in keychain on generation so we
            //  do not persist the public key.
            // .set_location(security_framework::item::Location::DataProtectionKeychain)
            .to_dictionary(),
    )?;

    let pubkey_hash = key1.public_key().unwrap().application_label().unwrap();

    add_item(
        ItemAddOptions::new(apple_security_framework::item::ItemAddValue::Ref(
            AddRef::Key(key1),
        ))
        .set_label(&label)
        .to_dictionary(),
    )?;

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
