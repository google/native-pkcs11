use std::{
    collections::HashMap,
    ffi::OsStr,
    io::{Read, Write},
    num::NonZeroIsize,
    str::FromStr,
    sync::Arc,
};

use native_pkcs11_traits::{Backend, Certificate, PrivateKey, PublicKey, Result};
use pem_rfc7468::{
    Base64Decoder,
    Error::{PostEncapsulationBoundary, PreEncapsulationBoundary},
};
use sha1::Digest as _;
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    handles::PersistentTpmHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricMode},
        key_bits::{AesKeyBits, RsaKeyBits},
        resource_handles::Hierarchy,
    },
    structures::{
        Digest,
        HashScheme,
        HashcheckTicket,
        MaxBuffer,
        Private,
        Public,
        PublicBuffer,
        PublicKeyRsa,
        PublicRsaParametersBuilder,
        SymmetricDefinitionObject,
    },
    tcti_ldr::DeviceConfig,
    traits::{Marshall, UnMarshall},
    tss2_esys::{TPM2B_DIGEST, TPMT_TK_HASHCHECK},
    Context,
    TctiNameConf,
};
use x509_cert::der::{Decode, Encode};

fn parse_tpm_key(key_pem: &str) -> Result<(Public, Private)> {
    let pub_start = key_pem
        .find("-----BEGIN TPM2 PUBLIC BLOB-----")
        .ok_or(PreEncapsulationBoundary)?;
    let pub_end = key_pem
        .find("-----END TPM2 PUBLIC BLOB-----")
        .ok_or(PostEncapsulationBoundary)?;
    let priv_start = key_pem
        .find("-----BEGIN TPM2 PRIVATE BLOB-----")
        .ok_or(PreEncapsulationBoundary)?;
    let priv_end = key_pem
        .find("-----END TPM2 PRIVATE BLOB-----")
        .ok_or(PostEncapsulationBoundary)?;
    let pub_pem = &key_pem[pub_start..pub_end + "-----END TPM2 PUBLIC BLOB-----".len()];
    let priv_pem = &key_pem[priv_start..priv_end + "-----END TPM2 PRIVATE BLOB-----".len()];

    let pub_bytes = pem_rfc7468::decode_vec(pub_pem.as_bytes())?.1;
    let priv_bytes = pem_rfc7468::decode_vec(priv_pem.as_bytes())?.1;

    let public = Public::unmarshall(&pub_bytes)?;
    let private = Private::try_from(priv_bytes)?;

    Ok((public, private))
}

fn null_hash_ticket() -> HashcheckTicket {
    TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: TPM2B_DIGEST::default(),
    }
    .try_into()
    .unwrap()
}

pub struct LinuxBackend {}

fn collect_credentials() -> Result<Vec<LinuxCredential>> {
    #[derive(Default)]
    struct KeyEntry {
        cert_pem: Option<Vec<u8>>,
        key_pem: Option<Vec<u8>>,
    }
    let mut key_entries_by_label = HashMap::<String, KeyEntry>::new();

    let certs_dir = std::env::var("NATIVE_PKCS11_CERTS_DIR").unwrap_or("/var/lib/certs".into());
    for file in std::fs::read_dir(certs_dir)? {
        let Ok(file) = file else {
            tracing::debug!("Failed to read DirEntry in certs dir: {file:?}");
            continue;
        };
        let path = file.path();
        let Some(label) = path.file_stem().map(OsStr::to_str).flatten() else {
            continue;
        };

        match file.path().extension().map(OsStr::to_str).flatten() {
            Some("crt") => {
                key_entries_by_label
                    .entry(label.into())
                    .or_default()
                    .cert_pem = Some(std::fs::read(file.path())?);
            }
            Some("key") => {
                key_entries_by_label
                    .entry(label.into())
                    .or_default()
                    .key_pem = Some(std::fs::read(file.path())?);
            }
            _ => {}
        }
    }

    let mut creds = vec![];

    for (label, entry) in key_entries_by_label {
        if let KeyEntry {
            cert_pem: Some(cert_pem),
            key_pem: Some(key_pem),
        } = entry
        {
            let cert = pem_rfc7468::decode_vec(&cert_pem);
            //TODO: assume tpm key for now
            let key = parse_tpm_key(&String::from_utf8_lossy(&key_pem));

            if let (Ok(cert), Ok((public, private))) = (cert, key) {
                if let Ok(parsed_cert) = x509_cert::Certificate::from_der(&cert.1) {
                    let spki = parsed_cert
                        .tbs_certificate
                        .subject_public_key_info
                        .to_der()?;
                    let cred = LinuxCredential {
                        label: label.clone(),
                        certificate: LinuxCertificate { der: cert.1 },
                        private_key: LinuxPrivateKey::Tpm(public, private),
                        public_key: LinuxPublicKey {
                            der: spki,
                            label: label.clone(),
                        },
                    };
                    creds.push(cred);
                }
            }
        }
    }

    Ok(creds)
}

impl native_pkcs11_traits::Backend for LinuxBackend {
    fn name(&self) -> String {
        "native-pkcs11-linux".into()
    }

    fn find_all_certificates(&self) -> native_pkcs11_traits::Result<Vec<Box<dyn Certificate>>> {
        Ok(collect_credentials()?
            .into_iter()
            .map(|c| Box::new(c) as Box<dyn Certificate>)
            .collect())
    }

    fn find_private_key(
        &self,
        query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn PrivateKey>>> {
        match query {
            native_pkcs11_traits::KeySearchOptions::Label(label) => {
                return Ok(collect_credentials()?
                    .into_iter()
                    .find(|c| c.label == label)
                    .map(|c| Arc::new(c) as Arc<dyn PrivateKey>));
            }
            native_pkcs11_traits::KeySearchOptions::PublicKeyHash(hash) => {
                return Ok(collect_credentials()?
                    .into_iter()
                    .find(|c| c.public_key_hash() == hash.to_vec())
                    .map(|c| Arc::new(c) as Arc<dyn PrivateKey>));
            }
        }
    }

    fn find_public_key(
        &self,
        query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Box<dyn PublicKey>>> {
        match query {
            native_pkcs11_traits::KeySearchOptions::Label(label) => {
                return Ok(collect_credentials()?
                    .into_iter()
                    .find(|c| c.label == label)
                    .map(|c| Box::new(c.public_key) as Box<dyn PublicKey>));
            }
            native_pkcs11_traits::KeySearchOptions::PublicKeyHash(hash) => {
                return Ok(collect_credentials()?
                    .into_iter()
                    .find(|c| c.public_key_hash() == hash.to_vec())
                    .map(|c| Box::new(c.public_key) as Box<dyn PublicKey>));
            }
        }
    }

    fn find_all_private_keys(&self) -> native_pkcs11_traits::Result<Vec<Arc<dyn PrivateKey>>> {
        let creds = collect_credentials()?;
        Ok(creds
            .into_iter()
            .map(|cred| Arc::new(cred) as Arc<dyn PrivateKey>)
            .collect())
    }

    fn find_all_public_keys(&self) -> native_pkcs11_traits::Result<Vec<Arc<dyn PublicKey>>> {
        let creds = collect_credentials()?;
        Ok(creds
            .into_iter()
            .map(|cred| Arc::new(cred.public_key) as Arc<dyn PublicKey>)
            .collect())
    }

    fn generate_key(
        &self,
        algorithm: native_pkcs11_traits::KeyAlgorithm,
        label: Option<&str>,
    ) -> native_pkcs11_traits::Result<Arc<dyn PrivateKey>> {
        todo!()
    }
}

fn rsa_srk_template() -> Public {
    let srk_template = Public::Rsa {
        /*
            FlagDecrypt | FlagRestricted | FlagFixedTPM |
            FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth
            | FlagNoDa
        */
        object_attributes: ObjectAttributesBuilder::new()
            .with_decrypt(true)
            .with_restricted(true)
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .build()
            .unwrap(),
        name_hashing_algorithm: HashingAlgorithm::Sha256,
        //https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
        auth_policy: Digest::try_from(vec![]).unwrap(),
        parameters: PublicRsaParametersBuilder::new()
            .with_symmetric(SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cfb,
            })
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_is_decryption_key(true)
            .with_is_signing_key(false)
            .with_restricted(true)
            .with_scheme(tss_esapi::structures::RsaScheme::Null)
            .build()
            .unwrap(),
        unique: PublicKeyRsa::new_empty_with_size(RsaKeyBits::Rsa2048),
    };
    srk_template
}

impl PrivateKey for LinuxCredential {
    fn public_key_hash(&self) -> Vec<u8> {
        self.public_key.public_key_hash()
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn sign(
        &self,
        algorithm: &native_pkcs11_traits::SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        match &self.private_key {
            LinuxPrivateKey::Raw(_) => todo!(),
            LinuxPrivateKey::Tpm(public, private) => {
                let mut ctx = tpm_context()?;
                let CREDKIT_SRK = PersistentTpmHandle::new(0x81000001).unwrap();
                let srk_tr = ctx.tr_from_tpm_public(CREDKIT_SRK.into()).unwrap();

                let key = ctx
                    .execute_with_nullauth_session(|ctx| {
                        ctx.load(srk_tr.into(), private.clone(), public.clone())
                    })
                    .unwrap();

                let scheme = match algorithm {
                    native_pkcs11_traits::SignatureAlgorithm::Ecdsa => {
                        tss_esapi::structures::SignatureScheme::EcDsa {
                            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                        }
                    }
                    _ => {
                        return Err("bad alg".into());
                    }
                };
                let sig = ctx.execute_with_nullauth_session(|ctx| {
                    ctx.sign(key, Digest::try_from(data)?, scheme, null_hash_ticket())
                })?;
                match sig {
                    tss_esapi::structures::Signature::EcDsa(sig) => {
                        let mut out = vec![];
                        out.extend_from_slice(sig.signature_r());
                        out.extend_from_slice(sig.signature_s());
                        Ok(out)
                    }
                    _ => Err("unexpected signature type".into()),
                }
            }
        }
    }

    fn delete(&self) {}

    fn algorithm(&self) -> native_pkcs11_traits::KeyAlgorithm {
        native_pkcs11_traits::KeyAlgorithm::Ecc
    }
}

fn tpm_context() -> Result<Context> {
    Ok(Context::new(
        TctiNameConf::from_environment_variable()
            .unwrap_or(TctiNameConf::Device(DeviceConfig::from_str("/dev/tpmrm0")?)),
    )?)
}

#[derive(Debug)]
struct LinuxCredential {
    label: String,
    certificate: LinuxCertificate,
    private_key: LinuxPrivateKey,
    public_key: LinuxPublicKey,
}

#[derive(Debug)]
struct LinuxCertificate {
    der: Vec<u8>,
}

impl Certificate for LinuxCredential {
    fn label(&self) -> String {
        self.label.clone()
    }

    fn to_der(&self) -> Vec<u8> {
        self.certificate.der.clone()
    }

    fn public_key(&self) -> &dyn PublicKey {
        &self.public_key
    }

    fn delete(self: Box<Self>) {
        todo!()
    }
}

enum LinuxPrivateKey {
    Raw(Vec<u8>),
    Tpm(Public, Private),
}

impl std::fmt::Debug for LinuxPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw(arg0) => f.debug_tuple("Raw").finish(),
            Self::Tpm(arg0, arg1) => f.debug_tuple("Tpm").field(arg0).field(arg1).finish(),
        }
    }
}

#[derive(Debug)]
struct LinuxPublicKey {
    label: String,
    der: Vec<u8>,
}

impl PublicKey for LinuxPublicKey {
    fn public_key_hash(&self) -> Vec<u8> {
        sha1::Sha1::digest(&self.der).as_slice().into()
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn to_der(&self) -> Vec<u8> {
        self.der.clone()
    }

    fn verify(
        &self,
        algorithm: &native_pkcs11_traits::SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        todo!()
    }

    fn delete(self: Box<Self>) {}

    fn algorithm(&self) -> native_pkcs11_traits::KeyAlgorithm {
        native_pkcs11_traits::KeyAlgorithm::Ecc
    }
}

#[test]
fn it_works() {
    LinuxBackend {}.find_all_private_keys().unwrap();
}

#[test]
fn test_rsa_srk_name() {
    use base64::Engine;
    let expected_public = r#"AAEACwADBHIAAAAGAIAAQwAQCAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"#;
    let expected_public_bytes = base64::engine::general_purpose::STANDARD
        .decode(expected_public)
        .unwrap();
    let expected =
        Public::try_from(PublicBuffer::try_from(expected_public_bytes).unwrap()).unwrap();

    assert_eq!(expected, rsa_srk_template());
}
