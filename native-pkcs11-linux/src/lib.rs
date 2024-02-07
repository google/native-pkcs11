use std::{collections::HashMap, ffi::OsStr, io::Read, str::FromStr, sync::Arc};

use native_pkcs11_traits::{Backend, Certificate, PrivateKey, PublicKey, Result};
use pem_rfc7468::{
    Base64Decoder,
    Error::{PostEncapsulationBoundary, PreEncapsulationBoundary},
};
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricMode},
        key_bits::{AesKeyBits, RsaKeyBits},
        resource_handles::Hierarchy,
    },
    structures::{
        Digest,
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
    Context,
    TctiNameConf,
};

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

pub struct LinuxBackend {}

impl native_pkcs11_traits::Backend for LinuxBackend {
    fn name(&self) -> String {
        "native-pkcs11-linux".into()
    }

    fn find_all_certificates(&self) -> native_pkcs11_traits::Result<Vec<Box<dyn Certificate>>> {
        todo!()
    }

    fn find_private_key(
        &self,
        query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn PrivateKey>>> {
        todo!()
    }

    fn find_public_key(
        &self,
        query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Box<dyn PublicKey>>> {
        todo!()
    }

    fn find_all_private_keys(&self) -> native_pkcs11_traits::Result<Vec<Arc<dyn PrivateKey>>> {
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
            dbg!(&label);
            if let KeyEntry {
                cert_pem: Some(cert_pem),
                key_pem: Some(key_pem),
            } = entry
            {
                let cert = pem_rfc7468::decode_vec(&cert_pem);
                //TODO: assume tpm key for now
                let key = parse_tpm_key(&String::from_utf8_lossy(&key_pem));

                if let (Ok(cert), Ok((public, private))) = (cert, key) {
                    let cred = LinuxCredential {
                        label,
                        certificate: LinuxCertificate { der: cert.1 },
                        private_key: LinuxPrivateKey::Tpm(public, private),
                    };
                    creds.push(cred);
                }
            }
        }
        todo!()
    }

    fn find_all_public_keys(&self) -> native_pkcs11_traits::Result<Vec<Arc<dyn PublicKey>>> {
        todo!()
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

impl PrivateKey for LinuxPrivateKey {
    fn public_key_hash(&self) -> Vec<u8> {
        todo!()
    }

    fn label(&self) -> String {
        todo!()
    }

    fn sign(
        &self,
        algorithm: &native_pkcs11_traits::SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        match self {
            LinuxPrivateKey::Raw(_) => todo!(),
            LinuxPrivateKey::Tpm(public, private) => {
                let ctx = tpm_context()?;
                todo!();
            }
        }
    }

    fn delete(&self) {
        todo!()
    }

    fn algorithm(&self) -> native_pkcs11_traits::KeyAlgorithm {
        todo!()
    }
}

fn tpm_context() -> Result<Context> {
    Ok(Context::new(
        TctiNameConf::from_environment_variable()
            .unwrap_or(TctiNameConf::Device(DeviceConfig::from_str("/dev/tpmrm0")?)),
    )?)
}

struct LinuxCredential {
    label: String,
    certificate: LinuxCertificate,
    private_key: LinuxPrivateKey,
}

struct LinuxCertificate {
    der: Vec<u8>,
}

enum LinuxPrivateKey {
    Raw(Vec<u8>),
    Tpm(Public, Private),
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
