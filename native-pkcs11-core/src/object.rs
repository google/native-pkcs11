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

use std::{ffi::CString, fmt::Debug, sync::Arc};

use native_pkcs11_traits::{
    backend,
    Certificate,
    CertificateExt,
    KeyAlgorithm,
    PrivateKey,
    PublicKey,
};
use p256::pkcs8::{
    der::{asn1::OctetString, Encode},
    AssociatedOid,
};
use pkcs1::{der::Decode, RsaPrivateKey, RsaPublicKey};
use pkcs11_sys::{
    CKC_X_509,
    CKK_EC,
    CKK_RSA,
    CKO_CERTIFICATE,
    CKO_PRIVATE_KEY,
    CKO_PROFILE,
    CKO_PUBLIC_KEY,
    CK_PROFILE_ID,
};
use tracing::warn;

use crate::attribute::{Attribute, AttributeType, Attributes};

#[derive(Debug)]
pub struct DataObject {
    pub application: CString,
    pub label: String,
    pub value: Vec<u8>,
}

// TODO(bweeks): resolve by improving the ObjectStore implementation.
#[allow(clippy::derive_hash_xor_eq)]
#[derive(Debug, Hash, Eq, Clone)]
pub enum Object {
    Certificate(Arc<dyn Certificate>),
    PrivateKey(Arc<dyn PrivateKey>),
    Profile(CK_PROFILE_ID),
    PublicKey(Arc<dyn PublicKey>),
}

//  #[derive(PartialEq)] fails to compile because it tries to move the Box<_>ed
//  values.
//  https://github.com/rust-lang/rust/issues/78808#issuecomment-723304465
impl PartialEq for Object {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Certificate(l0), Self::Certificate(r0)) => l0 == r0,
            (Self::PrivateKey(l0), Self::PrivateKey(r0)) => l0 == r0,
            (Self::Profile(l0), Self::Profile(r0)) => l0 == r0,
            (Self::PublicKey(l0), Self::PublicKey(r0)) => l0 == r0,
            (
                Self::Certificate(_) | Self::PrivateKey(_) | Self::Profile(_) | Self::PublicKey(_),
                _,
            ) => false,
        }
    }
}

impl Object {
    pub fn attribute(&self, type_: AttributeType) -> Option<Attribute> {
        match self {
            Object::Certificate(cert) => match type_ {
                AttributeType::CertificateType => Some(Attribute::CertificateType(CKC_X_509)),
                AttributeType::Class => Some(Attribute::Class(CKO_CERTIFICATE)),
                AttributeType::Id => Some(Attribute::Id(cert.public_key().public_key_hash())),
                AttributeType::Issuer => Some(Attribute::Issuer(cert.issuer())),
                AttributeType::Label => Some(Attribute::Label(cert.label())),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::SerialNumber => Some(Attribute::SerialNumber(cert.serial_number())),
                AttributeType::Subject => Some(Attribute::Subject(cert.subject())),
                AttributeType::Value => Some(Attribute::Value(cert.to_der())),
                _ => {
                    warn!("certificate: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::PrivateKey(private_key) => match type_ {
                AttributeType::AlwaysAuthenticate => Some(Attribute::AlwaysAuthenticate(false)),
                AttributeType::Class => Some(Attribute::Class(CKO_PRIVATE_KEY)),
                AttributeType::Decrypt => Some(Attribute::Decrypt(false)),
                AttributeType::EcParams => {
                    Some(Attribute::EcParams(p256::NistP256::OID.to_der().ok()?))
                }
                AttributeType::Id => Some(Attribute::Id(private_key.public_key_hash())),
                AttributeType::KeyType => Some(Attribute::KeyType(match private_key.algorithm() {
                    native_pkcs11_traits::KeyAlgorithm::Rsa => CKK_RSA,
                    native_pkcs11_traits::KeyAlgorithm::Ecc => CKK_EC,
                })),
                AttributeType::Label => Some(Attribute::Label(private_key.label())),
                AttributeType::Modulus => {
                    let modulus = private_key
                        .find_public_key(backend())
                        .ok()
                        .flatten()
                        .and_then(|public_key| {
                            let der = public_key.to_der();
                            RsaPublicKey::from_der(&der)
                                .map(|pk| pk.modulus.as_bytes().to_vec())
                                .ok()
                        });
                    modulus.map(Attribute::Modulus)
                }
                AttributeType::Prime1 => {
                    let key = private_key.to_der().unwrap();
                    let key = RsaPrivateKey::from_der(&key).unwrap();
                    Some(Attribute::Modulus(key.prime1.as_bytes().to_vec()))
                }
                AttributeType::Prime2 => {
                    let key = private_key.to_der().unwrap();
                    let key = RsaPrivateKey::from_der(&key).unwrap();
                    Some(Attribute::Modulus(key.prime2.as_bytes().to_vec()))
                }
                AttributeType::Private => Some(Attribute::Private(true)),
                AttributeType::PrivateExponent => {
                    let key = private_key.to_der().unwrap();
                    let key = RsaPrivateKey::from_der(&key).unwrap();
                    Some(Attribute::Modulus(key.private_exponent.as_bytes().to_vec()))
                }
                AttributeType::PublicExponent => {
                    let public_exponent = private_key
                        .find_public_key(backend())
                        .ok()
                        .flatten()
                        .and_then(|public_key| {
                            let der = public_key.to_der();
                            RsaPublicKey::from_der(&der)
                                .map(|pk| pk.public_exponent.as_bytes().to_vec())
                                .ok()
                        });
                    public_exponent.map(Attribute::PublicExponent)
                }
                AttributeType::Sign => Some(Attribute::Sign(true)),
                AttributeType::SignRecover => Some(Attribute::SignRecover(false)),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Unwrap => Some(Attribute::Unwrap(false)),
                _ => {
                    warn!("private_key: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::Profile(id) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PROFILE)),
                AttributeType::ProfileId => Some(Attribute::ProfileId(*id)),
                AttributeType::Token => Some(Attribute::Token(true)),
                _ => {
                    warn!("profile: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::PublicKey(pk) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PUBLIC_KEY)),
                AttributeType::Label => Some(Attribute::Label(pk.label())),
                AttributeType::Modulus => {
                    let key = pk.to_der();
                    let key = RsaPublicKey::from_der(&key).unwrap();
                    Some(Attribute::Modulus(key.modulus.as_bytes().to_vec()))
                }
                AttributeType::PublicExponent => {
                    let key = pk.to_der();
                    let key = RsaPublicKey::from_der(&key).unwrap();
                    Some(Attribute::Modulus(key.public_exponent.as_bytes().to_vec()))
                }
                AttributeType::KeyType => Some(Attribute::KeyType(match pk.algorithm() {
                    native_pkcs11_traits::KeyAlgorithm::Rsa => CKK_RSA,
                    native_pkcs11_traits::KeyAlgorithm::Ecc => CKK_EC,
                })),
                AttributeType::Id => Some(Attribute::Id(pk.public_key_hash())),
                AttributeType::EcPoint => {
                    if pk.algorithm() != KeyAlgorithm::Ecc {
                        return None;
                    }
                    let wrapped = OctetString::new(pk.to_der()).ok()?;
                    Some(Attribute::EcPoint(wrapped.to_der().ok()?))
                }
                _ => {
                    warn!("public_key: type_ unimplemented: {:?}", type_);
                    None
                }
            },
        }
    }

    pub fn matches(&self, others: &Attributes) -> bool {
        if let Some(class) = others.get(AttributeType::Class) {
            if *class != self.attribute(AttributeType::Class).unwrap() {
                return false;
            }
        }
        for other in &**others {
            if let Some(attr) = self.attribute(other.attribute_type()) {
                if *other != attr {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}
