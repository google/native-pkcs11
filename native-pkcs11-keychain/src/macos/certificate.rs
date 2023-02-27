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

use std::time::{Duration, SystemTime};

use native_pkcs11_traits::random_label;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, UIntRef},
    pkcs8::AssociatedOid,
};
use security_framework::{
    certificate::SecCertificate,
    identity::SecIdentity,
    item::{add_item, AddRef, ItemAddOptions, ItemClass, ItemSearchOptions, Reference},
    key::SecKey,
    os::macos::{identity::SecIdentityExt, keychain::SecKeychain},
};
use security_framework_sys::base::errSecItemNotFound;
use x509_cert::{
    der::{
        asn1::{GeneralizedTime, Ia5StringRef, OctetStringRef},
        oid::ObjectIdentifier,
        Decode,
        Encode,
    },
    ext::{
        pkix::{
            name::GeneralName,
            AuthorityKeyIdentifier,
            BasicConstraints,
            ExtendedKeyUsage,
            KeyUsage,
            KeyUsages,
            SubjectAltName,
            SubjectKeyIdentifier,
        },
        Extension,
    },
    name::{Name, RdnSequence},
    spki::{der::asn1::BitStringRef, EncodePublicKey, SubjectPublicKeyInfo},
    time::Validity,
    Certificate,
    TbsCertificate,
};

use crate::{
    key::{Algorithm, KeychainPublicKey},
    Result,
    LOGIN_KEYCHAIN_PATH,
};

pub struct KeychainCertificate {
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

pub fn import_certificate(der: &[u8]) -> Result<SecCertificate> {
    let cert = SecCertificate::from_der(der)?;

    let add_params = ItemAddOptions::new(security_framework::item::ItemAddValue::Ref(
        AddRef::Certificate(cert.clone()),
    ))
    .set_location(security_framework::item::Location::DefaultFileKeychain)
    .set_label(cert.subject_summary())
    .to_dictionary();
    add_item(add_params)?;

    Ok(cert)
}

pub fn find_certificate(pub_key_hash: &[u8]) -> Result<Option<SecIdentity>> {
    let results = ItemSearchOptions::new()
        .load_refs(true)
        .class(ItemClass::certificate())
        .pub_key_hash(pub_key_hash)
        .search()?;

    if results.is_empty() {
        return Ok(None);
    }

    let cert = match results.into_iter().next().ok_or("certificate not found")? {
        security_framework::item::SearchResult::Ref(Reference::Certificate(certificate)) => {
            certificate
        }
        _ => return Err("no key ref")?,
    };

    Ok(Some(SecIdentity::with_certificate(&[], &cert)?))
}

pub fn find_all_certificates() -> Result<Vec<SecIdentity>> {
    let results = ItemSearchOptions::new()
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

//  NOTE(kcking): After some empirical tests, it appears SecIdentity is really
//  just a SecCertificate that happens to have an associated SecKey private key
//  in the keychain. Both `SecItemAdd` and `SecItemDelete` treat a SecIdentity
//  like it is the underlying SecCertificate. Further reading:
//  https://stackoverflow.com/a/13041370.
//
//  For example, if we import a SecCertificate, then convert it to a SecIdentity
//  with SecIdentity::with_certificate, trying to import the resulting
//  SecIdentity will error with "already exists". Keychain is treating this
//  scenario as trying to import the same certificate twice.
//
//  An official Apple source also _hints_ at this behavior by saying "working
//  with identities as keychain items is very much like working with
//  certificates"
//  https://developer.apple.com/documentation/security/certificate_key_and_trust_services/identities/storing_an_identity_in_the_keychain?language=objc.
//
//  Overall, this means storing SecIdentities isn't any more useful to us than
//  storing SecCertificates. The main use case is using
//  `SecIdentity::with_certificate` to search for the private key corresponding
//  to a certificate.
pub fn import_identity(certificate: &SecCertificate) -> Result<SecIdentity> {
    let keychain = SecKeychain::open(LOGIN_KEYCHAIN_PATH)?;
    let identity = SecIdentity::with_certificate(&[keychain], certificate)?;

    let add_params = ItemAddOptions::new(security_framework::item::ItemAddValue::Ref(
        AddRef::Identity(identity.clone()),
    ))
    .set_location(security_framework::item::Location::DefaultFileKeychain)
    .set_label(certificate.subject_summary())
    .to_dictionary();

    match add_item(add_params) {
        Ok(_) => Ok(identity),
        Err(e)
            if e.message() == Some("The specified item already exists in the keychain.".into()) =>
        {
            Ok(identity)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod test {
    use native_pkcs11_traits::random_label;
    use serial_test::serial;

    use super::*;
    #[test]
    #[serial]
    fn test_self_signed_certificate() -> Result<()> {
        use security_framework::{
            item::{ItemClass, ItemSearchOptions, Limit},
            os::macos::item::ItemSearchOptionsExt,
        };

        use crate::key::generate_key;

        let label = random_label();
        let key = generate_key(Algorithm::RSA, &label)?;

        let cert = self_signed_certificate(Algorithm::RSA, &key)?;

        let cert = import_certificate(&cert)?;

        //  NOTE(kcking): Importing a certificate that has a private key already
        //  stored in the keychain will treat that certificate as an identity, even
        //  without calling import_identity.
        // let identity = import_identity(&cert)?;

        //  HACK(kcking): The macOS keychain takes some time to flush all of the updates
        // such that  they are visible to the next search query.
        std::thread::sleep(std::time::Duration::from_secs(1));

        assert!(
            ItemSearchOptions::new()
                .keychains(&[SecKeychain::open(LOGIN_KEYCHAIN_PATH)?])
                .class(ItemClass::identity())
                .limit(Limit::All)
                .load_refs(true)
                .search()?
                .iter()
                .any(|result| match result {
                    security_framework::item::SearchResult::Ref(
                        security_framework::item::Reference::Identity(id),
                    ) => id.certificate().unwrap().subject() == cert.subject(),
                    _ => false,
                })
        );

        //  Clean up
        cert.delete()?;
        //  NOTE(kcking): Deleting the certificate also deletes the identity since
        //  they are the same underlying object, so identity.delete() is not needed.
        // identity.delete()?;
        key.public_key().ok_or("no public key")?.delete()?;
        key.delete()?;
        Ok(())
    }
}

pub fn random_serial_number() -> [u8; 16] {
    use rand::Rng;
    rand::thread_rng().gen::<u128>().to_be_bytes()
}

const EXTENDED_KEY_USAGE_SERVER_AUTHENTICATION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// Demonstrate signing a certificate
pub fn self_signed_certificate(key_algorithm: Algorithm, private_key: &SecKey) -> Result<Vec<u8>> {
    let public_key = private_key
        .public_key()
        .ok_or("no public key")?
        .external_representation()
        .ok_or("no external representation")?
        .to_vec();

    let public_key = match key_algorithm {
        Algorithm::RSA => rsa::RsaPublicKey::from_pkcs1_der(&public_key)?
            .to_public_key_der()?
            .as_bytes()
            .to_owned(),
        Algorithm::ECC => p256::PublicKey::from_sec1_bytes(public_key.as_slice())?
            .to_public_key_der()?
            .as_bytes()
            .to_owned(),
    };

    let spki = SubjectPublicKeyInfo::try_from(public_key.as_slice())?;

    let subject_name =
        RdnSequence::encode_from_string(&format!("cn=Test Cert {}", random_label()))?;
    let issuer_name = RdnSequence::encode_from_string("cn=GShoe LLC")?;

    let serial_number = random_serial_number();

    let san = GeneralName::DnsName(Ia5StringRef::new("localhost")?);
    let san = SubjectAltName(vec![san]).to_vec()?;

    let key_usage = KeyUsage(
        KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment | KeyUsages::KeyAgreement,
    )
    .to_vec()?;

    let extended_key_usage = ExtendedKeyUsage(vec![
        EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION,
        EXTENDED_KEY_USAGE_SERVER_AUTHENTICATION,
    ])
    .to_vec()?;

    let basic_constraints = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    }
    .to_vec()?;

    let sk_and_ak_id = random_serial_number();
    let sk_id = SubjectKeyIdentifier(OctetStringRef::new(&sk_and_ak_id)?).to_vec()?;
    let ak_id = AuthorityKeyIdentifier {
        key_identifier: Some(OctetStringRef::new(&sk_and_ak_id)?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    }
    .to_vec()?;

    let tbs_certificate = TbsCertificate {
        version: x509_cert::Version::V3,
        //  NOTE: can't be empty
        serial_number: UIntRef::new(&serial_number)?,
        signature: spki.algorithm,
        issuer: Name::from_der(&issuer_name)?,
        validity: Validity {
            not_before: x509_cert::time::Time::GeneralTime(GeneralizedTime::from_system_time(
                SystemTime::now() - Duration::from_secs(60 * 60 * 24),
            )?),
            not_after: x509_cert::time::Time::GeneralTime(GeneralizedTime::from_system_time(
                SystemTime::now() + Duration::from_secs(60 * 60 * 24),
            )?),
        },
        subject: Name::from_der(&subject_name)?,
        subject_public_key_info: spki,

        //  webpki appears to not support these fields:
        //  https://github.com/briansmith/webpki/blob/17d9189981a618120fd8217a913828e7418e2484/src/cert.rs#L78
        issuer_unique_id: None,
        subject_unique_id: None,

        extensions: Some(vec![
            Extension {
                extn_id: BasicConstraints::OID,
                critical: true,
                extn_value: &basic_constraints,
            },
            Extension {
                extn_id: SubjectAltName::OID,
                critical: false,
                extn_value: &san,
            },
            Extension {
                extn_id: KeyUsage::OID,
                critical: true,
                extn_value: &key_usage,
            },
            Extension {
                extn_id: ExtendedKeyUsage::OID,
                critical: false,
                extn_value: &extended_key_usage,
            },
            Extension {
                extn_id: SubjectKeyIdentifier::OID,
                critical: false,
                extn_value: &sk_id,
            },
            Extension {
                extn_id: AuthorityKeyIdentifier::OID,
                critical: false,
                extn_value: &ak_id,
            },
        ]),
    };

    let payload = tbs_certificate.to_vec()?;
    let signature = private_key.create_signature(
        match key_algorithm {
            Algorithm::RSA => security_framework_sys::key::Algorithm::RSASignatureMessagePSSSHA256,
            Algorithm::ECC => {
                security_framework_sys::key::Algorithm::ECDSASignatureMessageX962SHA256
            }
        },
        &payload,
    )?;

    let cert = Certificate {
        tbs_certificate,
        signature_algorithm: spki.algorithm,
        signature: BitStringRef::from_bytes(signature.as_slice())?,
    };

    Ok(cert.to_vec()?)
}
