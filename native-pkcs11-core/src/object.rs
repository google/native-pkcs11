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

use der::{
    asn1::{ObjectIdentifier, OctetString},
    Encode,
};
use native_pkcs11_traits::{
    backend,
    Certificate,
    CertificateExt,
    KeyAlgorithm,
    PrivateKey,
    PublicKey,
};
use pkcs1::{der::Decode, RsaPublicKey};
use pkcs11_sys::{
    CKC_X_509,
    CKK_EC,
    CKK_RSA,
    CKO_CERTIFICATE,
    CKO_PRIVATE_KEY,
    CKO_PROFILE,
    CKO_PUBLIC_KEY,
    CK_CERTIFICATE_CATEGORY_UNSPECIFIED,
    CK_PROFILE_ID,
};
use spki::SubjectPublicKeyInfoRef;
use tracing::debug;

use crate::attribute::{Attribute, AttributeType, Attributes};

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

fn extract_ec_params(der_bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let spki: SubjectPublicKeyInfoRef<'_> = SubjectPublicKeyInfoRef::try_from(der_bytes).unwrap();
    // For EC keys, the algorithm parameters contain the curve OID
    // For EC keys, the subject public key is the EC point
    Some((
        ObjectIdentifier::from_bytes(spki.algorithm.parameters.unwrap().value())
            .unwrap()
            .to_der()
            .unwrap(),
        OctetString::new(spki.subject_public_key.raw_bytes()).unwrap().to_der().unwrap(),
    ))
}

fn extract_rsa_params(der_bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u64)> {
    // Parse the DER-encoded SPKI
    let spki: SubjectPublicKeyInfoRef<'_> = SubjectPublicKeyInfoRef::try_from(der_bytes).unwrap();
    // Parse the RSA public key bytes from the SPKI
    let rsa_pubkey = RsaPublicKey::from_der(spki.subject_public_key.raw_bytes()).ok()?;
    let modulus = rsa_pubkey.modulus.as_bytes();

    Some((
        modulus.to_vec(),
        rsa_pubkey.public_exponent.as_bytes().to_vec(),
        (modulus.len() * 8) as u64,
    ))
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
                AttributeType::Id => Some(Attribute::Id(cert.public_key().public_key_hash())),
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
                AttributeType::EcParams | AttributeType::EcPoint => {
                    if private_key.algorithm() != KeyAlgorithm::Ecc {
                        return None;
                    }
                    private_key.find_public_key(backend()).ok().flatten().and_then(|public_key| {
                        let der_bytes = public_key.to_der();
                        extract_ec_params(&der_bytes).map(|(params, point)| match type_ {
                            AttributeType::EcParams => Attribute::EcParams(params),
                            AttributeType::EcPoint => Attribute::EcPoint(point),
                            _ => unreachable!(),
                        })
                    })
                }
                AttributeType::Extractable => Some(Attribute::Extractable(false)),
                AttributeType::Id => Some(Attribute::Id(private_key.public_key_hash())),
                AttributeType::KeyType => Some(Attribute::KeyType(match private_key.algorithm() {
                    native_pkcs11_traits::KeyAlgorithm::Rsa => CKK_RSA,
                    native_pkcs11_traits::KeyAlgorithm::Ecc => CKK_EC,
                })),
                AttributeType::Label => Some(Attribute::Label(private_key.label())),
                AttributeType::Local => Some(Attribute::Local(false)),
                AttributeType::Modulus
                | AttributeType::ModulusBits
                | AttributeType::PublicExponent => {
                    if private_key.algorithm() != KeyAlgorithm::Rsa {
                        return None;
                    }
                    private_key.find_public_key(backend()).ok().flatten().and_then(|public_key| {
                        let der_bytes = public_key.to_der();
                        extract_rsa_params(&der_bytes).map(
                            |(modulus, exponent, bits)| match type_ {
                                AttributeType::Modulus => Attribute::Modulus(modulus),
                                AttributeType::ModulusBits => Attribute::ModulusBits(bits),
                                AttributeType::PublicExponent => {
                                    Attribute::PublicExponent(exponent)
                                }
                                _ => unreachable!(),
                            },
                        )
                    })
                }
                AttributeType::NeverExtractable => Some(Attribute::NeverExtractable(true)),
                AttributeType::Private => Some(Attribute::Private(true)),
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
                AttributeType::Verify => Some(Attribute::Verify(true)),
                AttributeType::VerifyRecover => Some(Attribute::VerifyRecover(false)),
                AttributeType::Wrap => Some(Attribute::Wrap(false)),
                AttributeType::Encrypt => Some(Attribute::Encrypt(false)),
                AttributeType::Derive => Some(Attribute::Derive(false)),
                AttributeType::Label => Some(Attribute::Label(pk.label())),
                AttributeType::Local => Some(Attribute::Local(false)),
                AttributeType::Modulus
                | AttributeType::ModulusBits
                | AttributeType::PublicExponent => {
                    if pk.algorithm() != KeyAlgorithm::Rsa {
                        return None;
                    }
                    let der_bytes = pk.to_der();
                    extract_rsa_params(&der_bytes).map(|(modulus, exponent, bits)| match type_ {
                        AttributeType::Modulus => Attribute::Modulus(modulus),
                        AttributeType::ModulusBits => Attribute::ModulusBits(bits),
                        AttributeType::PublicExponent => Attribute::PublicExponent(exponent),
                        _ => unreachable!(),
                    })
                }
                AttributeType::KeyType => Some(Attribute::KeyType(match pk.algorithm() {
                    native_pkcs11_traits::KeyAlgorithm::Rsa => CKK_RSA,
                    native_pkcs11_traits::KeyAlgorithm::Ecc => CKK_EC,
                })),
                AttributeType::Id => Some(Attribute::Id(pk.public_key_hash())),
                AttributeType::EcParams | AttributeType::EcPoint => {
                    if pk.algorithm() != KeyAlgorithm::Ecc {
                        return None;
                    }
                    let der_bytes = pk.to_der();
                    extract_ec_params(&der_bytes).map(|(params, point)| match type_ {
                        AttributeType::EcParams => Attribute::EcParams(params),
                        AttributeType::EcPoint => Attribute::EcPoint(point),
                        _ => unreachable!(),
                    })
                }
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
