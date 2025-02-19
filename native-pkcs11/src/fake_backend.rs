use std::{ptr::addr_of_mut, sync::Arc};

use native_pkcs11_traits::{Backend, KeyAlgorithm, register_backend};
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use rsa::RsaPrivateKey;

use crate::{CK_FUNCTION_LIST_PTR_PTR, CK_RV, CKR_OK, FUNC_LIST};

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    register_backend(Box::new(FakeBackend {}));
    unsafe { *ppFunctionList = addr_of_mut!(FUNC_LIST) };
    CKR_OK
}

struct FakeBackend {}

impl Backend for FakeBackend {
    fn name(&self) -> String {
        "native-pkcs11 fake backend".to_string()
    }

    fn find_all_certificates(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<Box<dyn native_pkcs11_traits::Certificate>>> {
        Ok(vec![])
    }

    fn find_private_key(
        &self,
        query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<std::sync::Arc<dyn native_pkcs11_traits::PrivateKey>>>
    {
        match query {
            native_pkcs11_traits::KeySearchOptions::Label(label) => {
                Ok(Some(Arc::new(PrivateKey::new(&label, KeyAlgorithm::Ecc))))
            }
            native_pkcs11_traits::KeySearchOptions::PublicKeyHash(_) => {
                Ok(Some(Arc::new(PrivateKey::new("TODO", KeyAlgorithm::Ecc))))
            }
        }
    }

    fn find_public_key(
        &self,
        query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Box<dyn native_pkcs11_traits::PublicKey>>> {
        match query {
            native_pkcs11_traits::KeySearchOptions::Label(_) => todo!(),
            native_pkcs11_traits::KeySearchOptions::PublicKeyHash(_) => {
                Ok(Some(Box::new(PrivateKey::new("TODO", KeyAlgorithm::Ecc))))
            }
        }
    }

    fn find_all_private_keys(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<std::sync::Arc<dyn native_pkcs11_traits::PrivateKey>>>
    {
        Ok(vec![])
    }

    fn find_all_public_keys(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<std::sync::Arc<dyn native_pkcs11_traits::PublicKey>>>
    {
        todo!()
    }

    fn generate_key(
        &self,
        algorithm: native_pkcs11_traits::KeyAlgorithm,
        _label: Option<&str>,
    ) -> native_pkcs11_traits::Result<std::sync::Arc<dyn native_pkcs11_traits::PrivateKey>> {
        let key = Arc::new(PrivateKey::new("TODO", algorithm));
        Ok(key)
    }
}

#[allow(clippy::large_enum_variant)]
#[allow(dead_code)]
#[derive(Debug)]
enum PrivateKey {
    Ecc(String, SigningKey),
    Rsa(String, RsaPrivateKey),
}

impl PrivateKey {
    fn new(label: &str, algorithm: KeyAlgorithm) -> Self {
        match algorithm {
            KeyAlgorithm::Rsa => {
                Self::Rsa(label.to_owned(), RsaPrivateKey::new(&mut OsRng, 2048).unwrap())
            }
            KeyAlgorithm::Ecc => Self::Ecc(label.to_owned(), SigningKey::random(&mut OsRng)),
        }
    }
}

impl native_pkcs11_traits::PrivateKey for PrivateKey {
    fn public_key_hash(&self) -> Vec<u8> {
        vec![0; 20]
    }

    fn label(&self) -> String {
        match self {
            Self::Ecc(label, _) => label.clone(),
            Self::Rsa(label, _) => label.clone(),
        }
    }

    fn sign(
        &self,
        _algorithm: &native_pkcs11_traits::SignatureAlgorithm,
        _data: &[u8],
    ) -> native_pkcs11_traits::Result<Vec<u8>> {
        todo!()
    }

    fn delete(&self) {}

    fn algorithm(&self) -> native_pkcs11_traits::KeyAlgorithm {
        match self {
            Self::Ecc(..) => KeyAlgorithm::Ecc,
            Self::Rsa(..) => KeyAlgorithm::Rsa,
        }
    }
}

impl native_pkcs11_traits::PublicKey for PrivateKey {
    fn public_key_hash(&self) -> Vec<u8> {
        todo!()
    }

    fn label(&self) -> String {
        todo!()
    }

    fn to_der(&self) -> Vec<u8> {
        todo!()
    }

    fn verify(
        &self,
        _algorithm: &native_pkcs11_traits::SignatureAlgorithm,
        _data: &[u8],
        _signature: &[u8],
    ) -> native_pkcs11_traits::Result<()> {
        todo!()
    }

    fn delete(self: Box<Self>) {}

    fn algorithm(&self) -> KeyAlgorithm {
        todo!()
    }
}
