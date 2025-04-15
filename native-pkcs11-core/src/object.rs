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

use der::{Encode, asn1::OctetString};
use native_pkcs11_traits::{
    Certificate,
    CertificateExt,
    KeyAlgorithm,
    PrivateKey,
    PublicKey,
    backend,
};
use pkcs1::{RsaPublicKey, der::Decode};
use pkcs11_sys::{
    CK_CERTIFICATE_CATEGORY_UNSPECIFIED,
    CK_PROFILE_ID,
    CKC_X_509,
    CKK_EC,
    CKK_RSA,
    CKO_CERTIFICATE,
    CKO_PRIVATE_KEY,
    CKO_PROFILE,
    CKO_PUBLIC_KEY,
};
use tracing::debug;

use crate::attribute::{Attribute, AttributeType, Attributes};

const P256_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

#[derive(Debug)]
pub struct DataObject {
    pub application: CString,
    pub label: String,
    pub value: Vec<u8>,
}

// Usage of generics is a workaround for the following issue:
// https://github.com/rust-lang/rust/issues/78808#issuecomment-1664416547
#[derive(Debug, PartialEq, Hash, Eq)]
pub enum Object<
    DynCertificate: ?Sized + PartialEq = dyn Certificate,
    DynPrivateKey: ?Sized + PartialEq = dyn PrivateKey,
    DynPublicKey: ?Sized + PartialEq = dyn PublicKey,
> {
    Certificate(Arc<DynCertificate>),
    PrivateKey(Arc<DynPrivateKey>),
    Profile(CK_PROFILE_ID),
    PublicKey(Arc<DynPublicKey>),
}

impl Clone for Object {
    fn clone(&self) -> Self {
        match self {
            Object::Certificate(cert) => Object::Certificate(cert.clone()),
            Object::PrivateKey(private_key) => Object::PrivateKey(private_key.clone()),
            Object::Profile(id) => Object::Profile(*id),
            Object::PublicKey(public_key) => Object::PublicKey(public_key.clone()),
        }
    }
}

impl Object {
    pub fn attribute(&self, type_: AttributeType) -> Option<Attribute> {
        match self {
            Object::Certificate(cert) => match type_ {
                AttributeType::CertificateCategory => {
                    Some(Attribute::CertificateCategory(CK_CERTIFICATE_CATEGORY_UNSPECIFIED))
                }
                AttributeType::CertificateType => Some(Attribute::CertificateType(CKC_X_509)),
                AttributeType::Class => Some(Attribute::Class(CKO_CERTIFICATE)),
                AttributeType::Id => Some(Attribute::Id(cert.id())),
                AttributeType::Issuer => Some(Attribute::Issuer(cert.issuer())),
                AttributeType::Label => Some(Attribute::Label(cert.label())),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Trusted => Some(Attribute::Trusted(false)),
                AttributeType::SerialNumber => Some(Attribute::SerialNumber(cert.serial_number())),
                AttributeType::Subject => Some(Attribute::Subject(cert.subject())),
                AttributeType::Value => Some(Attribute::Value(cert.to_der())),
                _ => {
                    debug!("certificate: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::PrivateKey(private_key) => match type_ {
                AttributeType::AlwaysSensitive => Some(Attribute::AlwaysSensitive(true)),
                AttributeType::AlwaysAuthenticate => Some(Attribute::AlwaysAuthenticate(false)),
                AttributeType::Class => Some(Attribute::Class(CKO_PRIVATE_KEY)),
                AttributeType::Decrypt => Some(Attribute::Decrypt(false)),
                AttributeType::Derive => Some(Attribute::Derive(false)),
                AttributeType::EcParams => Some(Attribute::EcParams(P256_OID.to_der().ok()?)),
                AttributeType::Extractable => Some(Attribute::Extractable(false)),
                AttributeType::Id => Some(Attribute::Id(private_key.id())),
                AttributeType::KeyType => Some(Attribute::KeyType(match private_key.algorithm() {
                    native_pkcs11_traits::KeyAlgorithm::Rsa => CKK_RSA,
                    native_pkcs11_traits::KeyAlgorithm::Ecc => CKK_EC,
                })),
                AttributeType::Label => Some(Attribute::Label(private_key.label())),
                AttributeType::Local => Some(Attribute::Local(false)),
                AttributeType::Modulus => {
                    let modulus = private_key.find_public_key(backend()).ok().flatten().and_then(
                        |public_key| {
                            let der = public_key.to_der();
                            RsaPublicKey::from_der(&der)
                                .map(|pk| pk.modulus.as_bytes().to_vec())
                                .ok()
                        },
                    );
                    modulus.map(Attribute::Modulus)
                }
                AttributeType::NeverExtractable => Some(Attribute::NeverExtractable(true)),
                AttributeType::Private => Some(Attribute::Private(true)),
                AttributeType::PublicExponent => {
                    let public_exponent =
                        private_key.find_public_key(backend()).ok().flatten().and_then(
                            |public_key| {
                                let der = public_key.to_der();
                                RsaPublicKey::from_der(&der)
                                    .map(|pk| pk.public_exponent.as_bytes().to_vec())
                                    .ok()
                            },
                        );
                    public_exponent.map(Attribute::PublicExponent)
                }
                AttributeType::Sensitive => Some(Attribute::Sensitive(true)),
                AttributeType::Sign => Some(Attribute::Sign(true)),
                AttributeType::SignRecover => Some(Attribute::SignRecover(false)),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Unwrap => Some(Attribute::Unwrap(false)),
                _ => {
                    debug!("private_key: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::Profile(id) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PROFILE)),
                AttributeType::ProfileId => Some(Attribute::ProfileId(*id)),
                AttributeType::Token => Some(Attribute::Token(true)),
                _ => {
                    debug!("profile: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::PublicKey(pk) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PUBLIC_KEY)),
                AttributeType::Derive => Some(Attribute::Derive(false)),
                AttributeType::Label => Some(Attribute::Label(pk.label())),
                AttributeType::Local => Some(Attribute::Local(false)),
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
                AttributeType::Id => Some(Attribute::Id(pk.id())),
                AttributeType::EcPoint => {
                    if pk.algorithm() != KeyAlgorithm::Ecc {
                        return None;
                    }
                    let wrapped = OctetString::new(pk.to_der()).ok()?;
                    Some(Attribute::EcPoint(wrapped.to_der().ok()?))
                }
                AttributeType::EcParams => Some(Attribute::EcParams(P256_OID.to_der().ok()?)),
                _ => {
                    debug!("public_key: type_ unimplemented: {:?}", type_);
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
        for other in others {
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
