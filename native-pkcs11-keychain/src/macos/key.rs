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

use std::fmt::Debug;

use core_foundation::base::ToVoid;
use native_pkcs11_traits::{KeyAlgorithm, PrivateKey, PublicKey, SignatureAlgorithm};
use security_framework::{
    item::{ItemClass, KeyClass, Limit, Location, Reference},
    key::{GenerateKeyOptions, KeyType, SecKey},
};
// TODO(bweeks,kcking): remove dependency on security-framework-sys crate.
use security_framework_sys::item::{
    kSecAttrKeyType,
    kSecAttrKeyTypeEC,
    kSecAttrKeyTypeRSA,
    kSecAttrTokenID,
};
use tracing::instrument;

use crate::Result;

#[derive(Debug)]
pub enum Algorithm {
    RSA,
    ECC,
}

fn sigalg_to_seckeyalg(
    signature_algorithm: &SignatureAlgorithm,
) -> Result<security_framework_sys::key::Algorithm> {
    use security_framework_sys::key::Algorithm::*;
    let alg = match signature_algorithm {
        native_pkcs11_traits::SignatureAlgorithm::Ecdsa => ECDSASignatureRFC4754,
        native_pkcs11_traits::SignatureAlgorithm::RsaRaw => RSASignatureRaw,
        native_pkcs11_traits::SignatureAlgorithm::RsaPkcs1v15Raw => RSASignatureDigestPKCS1v15Raw,
        native_pkcs11_traits::SignatureAlgorithm::RsaPkcs1v15Sha1 => {
            RSASignatureMessagePKCS1v15SHA1
        }
        native_pkcs11_traits::SignatureAlgorithm::RsaPkcs1v15Sha384 => {
            RSASignatureMessagePKCS1v15SHA384
        }
        native_pkcs11_traits::SignatureAlgorithm::RsaPkcs1v15Sha256 => {
            RSASignatureMessagePKCS1v15SHA256
        }
        native_pkcs11_traits::SignatureAlgorithm::RsaPkcs1v15Sha512 => {
            RSASignatureMessagePKCS1v15SHA512
        }
        native_pkcs11_traits::SignatureAlgorithm::RsaPss {
            digest,
            mask_generation_function,
            salt_length,
        } => {
            //  SecurityFramework only supports digest == mgf, salt_length == len(digest).
            if digest != mask_generation_function || digest.digest_len() != *salt_length as usize {
                return Err(crate::ErrorKind::UnsupportedSignatureAlgorithm(
                    signature_algorithm.clone(),
                )
                .into());
            }
            match mask_generation_function {
                native_pkcs11_traits::DigestType::Sha1 => RSASignatureDigestPSSSHA1,
                native_pkcs11_traits::DigestType::Sha224 => RSASignatureDigestPSSSHA224,
                native_pkcs11_traits::DigestType::Sha256 => RSASignatureDigestPSSSHA256,
                native_pkcs11_traits::DigestType::Sha384 => RSASignatureDigestPSSSHA384,
                native_pkcs11_traits::DigestType::Sha512 => RSASignatureDigestPSSSHA512,
            }
        }
    };
    Ok(alg)
}

#[derive(Debug)]
pub struct KeychainPrivateKey {
    sec_key: SecKey,
    label: String,
    public_key_hash: Vec<u8>,
    algorithm: KeyAlgorithm,
    pub_key: Option<KeychainPublicKey>,
}

impl KeychainPrivateKey {
    #[instrument]
    pub fn new(
        sec_key: SecKey,
        label: impl Into<String> + Debug,
        pub_key: Option<KeychainPublicKey>,
    ) -> Result<Self> {
        let label = label.into();
        let public_key_hash = sec_key.application_label().ok_or("no application_label")?;
        Ok(Self {
            algorithm: sec_key_algorithm(&sec_key)?,
            sec_key,
            label,
            public_key_hash,
            pub_key,
        })
    }
}

impl PrivateKey for KeychainPrivateKey {
    #[instrument]
    fn public_key_hash(&self) -> Vec<u8> {
        self.public_key_hash.clone()
    }

    #[instrument]
    fn label(&self) -> String {
        self.label.clone()
    }

    #[instrument]
    fn sign(
        &self,
        algorithm: &native_pkcs11_traits::SignatureAlgorithm,
        data: &[u8],
    ) -> native_pkcs11_traits::Result<Vec<u8>> {
        let algorithm = sigalg_to_seckeyalg(algorithm)?;
        Ok(self.sec_key.create_signature(algorithm, data.as_ref())?)
    }

    #[instrument]
    fn delete(&self) {
        let _ = self.sec_key.delete();
    }

    #[instrument]
    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }
    fn find_public_key(
        &self,
        _backend: &dyn native_pkcs11_traits::Backend,
    ) -> native_pkcs11_traits::Result<Option<Box<dyn PublicKey>>> {
        let sec_copy = self
            .sec_key
            .public_key()
            .map(|sec_key| KeychainPublicKey::new(sec_key, self.label()))
            .transpose()
            .ok()
            .flatten()
            .map(|key| Box::new(key) as _);
        if sec_copy.is_some() {
            return Ok(sec_copy);
        }
        Ok(self.pub_key.clone().map(|key| Box::new(key) as _))
    }
}

fn sec_key_algorithm(sec_key: &SecKey) -> Result<KeyAlgorithm> {
    let attributes = sec_key.attributes();
    if attributes
        .find(unsafe { kSecAttrTokenID }.to_void())
        .is_some()
    {
        //  The only possible kSecAttrtokenID is kSecAttrTokenIDSecureEnclave.
        //
        //  SecureEnclave keys do not have kSecAttrKeyType populated, but we can
        //  assume they are Ecc.
        return Ok(KeyAlgorithm::Ecc);
    }
    let key_ty = sec_key
        .attributes()
        .find(unsafe { kSecAttrKeyType }.to_void())
        .and_then(|key_type| match *key_type as *const _ {
            ty if ty == unsafe { kSecAttrKeyTypeRSA } => Some(KeyAlgorithm::Rsa),
            ty if ty == unsafe { kSecAttrKeyTypeEC } => Some(KeyAlgorithm::Ecc),
            _ => None,
        })
        .ok_or("no key type")?;
    Ok(key_ty)
}

#[derive(Debug, Clone)]
pub struct KeychainPublicKey {
    pub sec_key: SecKey,
    pub label: String,
    der: Vec<u8>,
    public_key_hash: Vec<u8>,
    algorithm: KeyAlgorithm,
}

impl KeychainPublicKey {
    #[instrument]
    pub fn new(sec_key: SecKey, label: impl Into<String> + Debug) -> Result<Self> {
        let der = sec_key
            .external_representation()
            .ok_or("no external representation")?;
        let key_ty = sec_key_algorithm(&sec_key)?;
        Ok(Self {
            public_key_hash: sec_key.application_label().ok_or("no application_label")?,
            sec_key,
            label: label.into(),
            der: der.to_vec(),
            algorithm: key_ty,
        })
    }
}

impl PublicKey for KeychainPublicKey {
    #[instrument]
    fn public_key_hash(&self) -> Vec<u8> {
        self.public_key_hash.clone()
    }

    #[instrument]
    fn label(&self) -> String {
        self.label.clone()
    }

    #[instrument]
    fn to_der(&self) -> Vec<u8> {
        self.der.clone()
    }

    #[instrument]
    fn verify(
        &self,
        algorithm: &native_pkcs11_traits::SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> native_pkcs11_traits::Result<()> {
        let algorithm = sigalg_to_seckeyalg(algorithm)?;
        let result = self.sec_key.verify_signature(algorithm, data, signature)?;
        if !result {
            return Err("verify failed")?;
        }
        Ok(())
    }

    fn delete(self: Box<Self>) {
        let _ = self.sec_key.delete();
    }

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }
}

#[instrument(skip(location))]
pub fn generate_key(
    algorithm: Algorithm,
    label: &str,
    location: Option<Location>,
) -> Result<SecKey> {
    let (ty, size) = match algorithm {
        Algorithm::RSA => (KeyType::rsa(), 2048),
        Algorithm::ECC => (KeyType::ec(), 256),
    };

    let opts = GenerateKeyOptions {
        key_type: Some(ty),
        size_in_bits: Some(size),
        label: Some(label.into()),
        token: Some(security_framework::key::Token::Software),
        location,
        access_control: None,
    };

    Ok(SecKey::new(&opts).map_err(|e| e.to_string())?)
}

pub fn find_key(class: KeyClass, label: &str) -> Result<SecKey> {
    let results = crate::keychain::item_search_options()?
        .load_refs(true)
        .label(label)
        .class(ItemClass::key())
        .key_class(class)
        .limit(1)
        .search();

    let loaded_key = match results?.into_iter().next().ok_or("key not found")? {
        security_framework::item::SearchResult::Ref(Reference::Key(key)) => key,
        _ => return Err("no key ref")?,
    };

    Ok(loaded_key)
}

#[instrument]
pub fn find_key2(class: KeyClass, label: &[u8]) -> Result<Option<SecKey>> {
    let results = crate::keychain::item_search_options()?
        .load_refs(true)
        .class(ItemClass::key())
        .key_class(class)
        .application_label(label)
        .limit(1)
        .search();

    let results = match results {
        Err(e) if e.code() == -25300 => return Ok(None),
        Err(e) => return Err(e)?,
        Ok(results) => results,
    };

    let loaded_key = results
        .into_iter()
        .next()
        .map(|key| match key {
            security_framework::item::SearchResult::Ref(Reference::Key(key)) => Ok::<_, &str>(key),
            _ => Err("no key ref")?,
        })
        .transpose()?;

    Ok(loaded_key)
}

#[instrument]
pub fn find_all_keys(key_class: KeyClass) -> Result<Vec<SecKey>> {
    let results = crate::keychain::item_search_options()?
        .load_refs(true)
        .class(ItemClass::key())
        .key_class(key_class)
        .limit(Limit::All)
        .search();

    let results = match results {
        Err(e) if e.code() == -25300 => return Ok(vec![]),
        Err(e) => return Err(e)?,
        Ok(results) => results,
    };

    let keys = results
        .into_iter()
        .filter_map(|res| match res {
            security_framework::item::SearchResult::Ref(Reference::Key(key)) => Some(key),
            _ => None,
        })
        .collect();

    Ok(keys)
}

#[cfg(test)]
mod test {
    use core_foundation::base::{TCFType, ToVoid};
    use native_pkcs11_traits::{random_label, Backend};
    use security_framework::item::{AddRef, ItemAddOptions, Limit};
    use security_framework_sys::item::{kSecAttrLabel, kSecValueRef};
    use serial_test::serial;

    use super::*;
    use crate::{keychain, KeychainBackend};
    #[test]
    #[serial]
    fn key_label() -> crate::Result<()> {
        let label = random_label();
        let key = generate_key(Algorithm::RSA, &label, Some(keychain::location()?))?;

        let mut found = false;
        for res in crate::keychain::item_search_options()?
            .key_class(KeyClass::private())
            .limit(Limit::Max(1))
            .load_attributes(true)
            .load_refs(true)
            .label(&label)
            .search()?
        {
            found = true;
            let (found_key, found_label) = match res {
                security_framework::item::SearchResult::Ref(_) => panic!(),
                security_framework::item::SearchResult::Dict(d) => {
                    let key = unsafe {
                        SecKey::wrap_under_get_rule(d.get(kSecValueRef.to_void()).cast_mut().cast())
                    };
                    let label = unsafe {
                        core_foundation::string::CFString::wrap_under_get_rule(
                            d.get(kSecAttrLabel.to_void()).cast_mut().cast(),
                        )
                    };
                    (key, label.to_string())
                }
                security_framework::item::SearchResult::Data(_) => panic!(),
                security_framework::item::SearchResult::Other => panic!(),
            };

            assert_eq!(
                found_key.external_representation().unwrap().to_vec(),
                key.external_representation().unwrap().to_vec()
            );

            assert_eq!(found_label, label);
        }
        key.public_key().unwrap().delete()?;
        key.delete()?;
        assert!(found);
        Ok(())
    }

    #[test]
    #[serial]
    fn key_lifecycle() -> Result<()> {
        for (key_alg, sig_alg) in [
            (
                Algorithm::ECC,
                security_framework_sys::key::Algorithm::ECDSASignatureDigestX962,
            ),
            (
                Algorithm::RSA,
                security_framework_sys::key::Algorithm::RSASignatureDigestPKCS1v15Raw,
            ),
        ] {
            let label = &random_label();

            let key = generate_key(key_alg, label, Some(keychain::location()?))?;

            let first_pubkey = key
                .public_key()
                .ok_or("no pubkey")?
                .external_representation()
                .ok_or("no external_representation")?
                .to_vec();

            std::mem::drop(key);

            let loaded_key = find_key(KeyClass::private(), label)?;

            let payload = vec![0u8; 32];
            let signature = loaded_key.create_signature(sig_alg, &payload)?;

            let loaded_pubkey = loaded_key.public_key().ok_or("no pubkey")?;
            let sig_valid = loaded_pubkey.verify_signature(sig_alg, &payload, &signature)?;
            assert!(sig_valid);

            assert_eq!(
                loaded_pubkey.external_representation().unwrap().to_vec(),
                first_pubkey
            );

            loaded_key.public_key().ok_or("no pubkey")?.delete()?;
            loaded_key.delete()?;
        }

        Ok(())
    }

    #[test]
    #[ignore]
    fn stress_test_keygen() {
        let try_gen_key = || -> bool {
            let label = random_label();
            match generate_key(Algorithm::RSA, &label, Some(keychain::location().unwrap())) {
                Ok(key) => {
                    let _ = key.delete();
                    true
                }
                Err(e) => {
                    eprintln!("{:?}", e);
                    false
                }
            }
        };

        let mut handles = vec![];
        for _ in 0..20 {
            handles.push(std::thread::spawn(try_gen_key));
        }
        //  fold so we don't early exit other threads
        assert!(handles.into_iter().all(|h| h.join().unwrap()));
    }

    #[test]
    #[ignore = "https://github.com/google/native-pkcs11/issues/302"]
    fn keychain_pubkey_hash_find() -> Result<()> {
        let key1 = generate_key(Algorithm::ECC, &random_label(), Some(keychain::location()?))?;
        let key2 = generate_key(Algorithm::ECC, &random_label(), Some(keychain::location()?))?;
        assert_ne!(key1.application_label(), key2.application_label());

        for keyclass in [KeyClass::public(), KeyClass::private()] {
            for key in [&key1, &key2] {
                assert_eq!(
                    find_key2(keyclass, &key.application_label().unwrap())?
                        .unwrap()
                        .application_label()
                        .unwrap(),
                    key.application_label().unwrap()
                );
            }
        }

        for key in [&key1, &key2] {
            key.public_key().as_ref().map(SecKey::delete);
            let _ = key.delete();
        }

        Ok(())
    }

    #[test]
    #[ignore = "demonstrate bug"]
    fn unpersisted_public_key() -> Result<()> {
        //  NOTE(kcking):
        //  1) Manually-imported keys are super scuffed.
        //  Manually imported key can be searched by label (if imported with
        //  that label), but cannot be searched by application_label (aka public
        //  key hash). Perhaps we are supposed to set this value at import time.
        //
        //  2) Manually-imported private keys do not return a corresponding
        //  public key from SecKeyCopyPublicKey (`.public_key()` in rust).

        let label = random_label();
        let key1 = SecKey::new(
            GenerateKeyOptions::default()
                .set_key_type(KeyType::ec())
                .set_label(&label),
        )?;

        let pubkey_hash = key1.public_key().unwrap().application_label().unwrap();

        ItemAddOptions::new(security_framework::item::ItemAddValue::Ref(AddRef::Key(
            key1,
        )))
        .set_label(&label)
        .add()?;

        //  NOTE(kcking): this fails to find the generated key, most likely
        //  because application_label is not automatically populated by
        //  SecurityFramework when importing a SecKey
        //
        //  let found_key =
        //     KeychainBackend::find_private_key(native_pkcs11_traits::KeySearchOptions::PublicKeyHash(
        //         pubkey_hash
        //             .as_slice()
        //             .try_into()
        //             .map_err(|_| "into array")?,
        //     ))
        //     .map_err(|e| {
        //         dbg!(e);
        //         "find"
        //     })?
        //     .unwrap();

        let found_key = KeychainBackend
            .find_private_key(native_pkcs11_traits::KeySearchOptions::Label(label))
            .map_err(|e| {
                dbg!(e);
                "find"
            })?
            .unwrap();

        assert_eq!(pubkey_hash, found_key.public_key_hash());

        Ok(())
    }
}
