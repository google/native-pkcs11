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

use native_pkcs11_traits::SignatureAlgorithm;
use once_cell::sync::Lazy;
use pkcs11_sys::*;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::Error;

#[derive(EnumIter)]
pub enum Mechanism {
    Ecdsa,
    RsaPkcs,
    RsaPkcsSha1,
    RsaPkcsSha256,
    RsaPkcsSha384,
    RsaPkcsSha512,
    RsaX509,
}

pub static MECHANISMS: Lazy<Vec<CK_MECHANISM_TYPE>> =
    Lazy::new(|| Mechanism::iter().map(|m| m.into()).collect());

impl TryFrom<CK_MECHANISM_TYPE> for Mechanism {
    type Error = Error;

    fn try_from(value: CK_MECHANISM_TYPE) -> Result<Self, Self::Error> {
        match value {
            CKM_ECDSA => Ok(Mechanism::Ecdsa),
            CKM_RSA_PKCS => Ok(Mechanism::RsaPkcs),
            CKM_RSA_X_509 => Ok(Mechanism::RsaX509),
            CKM_SHA1_RSA_PKCS => Ok(Mechanism::RsaPkcsSha1),
            CKM_SHA256_RSA_PKCS => Ok(Mechanism::RsaPkcsSha256),
            CKM_SHA384_RSA_PKCS => Ok(Mechanism::RsaPkcsSha384),
            CKM_SHA512_RSA_PKCS => Ok(Mechanism::RsaPkcsSha512),
            _ => Err(Error::MechanismInvalid(value)),
        }
    }
}

impl From<Mechanism> for CK_MECHANISM_TYPE {
    fn from(mechanism: Mechanism) -> Self {
        match mechanism {
            Mechanism::Ecdsa => CKM_ECDSA,
            Mechanism::RsaPkcs => CKM_RSA_PKCS,
            Mechanism::RsaPkcsSha1 => CKM_SHA1_RSA_PKCS,
            Mechanism::RsaPkcsSha256 => CKM_SHA256_RSA_PKCS,
            Mechanism::RsaPkcsSha384 => CKM_SHA384_RSA_PKCS,
            Mechanism::RsaPkcsSha512 => CKM_SHA512_RSA_PKCS,
            Mechanism::RsaX509 => CKM_RSA_X_509,
        }
    }
}

impl From<Mechanism> for SignatureAlgorithm {
    fn from(mechanism: Mechanism) -> Self {
        match mechanism {
            Mechanism::Ecdsa => SignatureAlgorithm::Ecdsa,
            Mechanism::RsaPkcs => SignatureAlgorithm::RsaPkcs1v15Raw,
            Mechanism::RsaPkcsSha1 => SignatureAlgorithm::RsaPkcs1v15Sha1,
            Mechanism::RsaPkcsSha256 => SignatureAlgorithm::RsaPkcs1v15Sha256,
            Mechanism::RsaPkcsSha384 => SignatureAlgorithm::RsaPkcs1v15Sha512,
            Mechanism::RsaPkcsSha512 => SignatureAlgorithm::RsaPkcs1v15Sha384,
            Mechanism::RsaX509 => SignatureAlgorithm::RsaRaw,
        }
    }
}
