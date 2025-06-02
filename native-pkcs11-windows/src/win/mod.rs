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
#![allow(dead_code, unused_variables)]

use std::{ffi::OsString, ops::Deref, str::FromStr, sync::Arc};

use native_pkcs11_traits::Backend;
use windows::{
    Security::Cryptography::Certificates::CertificateStores,
    Storage::Streams::{Buffer, IBuffer},
    Win32::System::WinRT::IBufferByteAccess,
    core::Interface,
};

//  https://stackoverflow.com/questions/2742739/how-do-i-know-what-the-storename-of-a-certificate-is
const STORE_NAME: &str = "My";

struct Bytes(Buffer);

impl From<&[u8]> for Bytes {
    fn from(in_data: &[u8]) -> Self {
        let buffer = Buffer::Create(in_data.len().try_into().unwrap()).unwrap();
        buffer.SetLength(in_data.len().try_into().unwrap()).unwrap();
        let interop = buffer.cast::<IBufferByteAccess>().unwrap();
        let data_ptr = unsafe { interop.Buffer() }.unwrap();

        let s =
            unsafe { std::slice::from_raw_parts_mut(data_ptr, buffer.Length().unwrap() as usize) };
        s.copy_from_slice(in_data);
        Self(buffer)
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let interop = self.0.cast::<IBufferByteAccess>().unwrap();
        let data_ptr = unsafe { interop.Buffer() }.unwrap();
        unsafe { std::slice::from_raw_parts(data_ptr, self.0.Length().unwrap() as usize) }
    }
}

impl Bytes {
    pub fn as_buffer_ref(&self) -> IBuffer {
        //  TODO(kcking): is this safe, or do we need to ensure Self outlives IBuffer
        self.0.cast().unwrap()
    }
}

pub struct WindowsBackend {}
impl Backend for WindowsBackend {
    fn find_all_certificates(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<Box<dyn native_pkcs11_traits::Certificate>>> {
        let store_name = OsString::from_str(STORE_NAME)?;
        let store = CertificateStores::GetStoreByName(&store_name.into()).unwrap();

        todo!()
    }

    fn find_private_key(
        &self,
        _query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn native_pkcs11_traits::PrivateKey>>> {
        Ok(None)
    }

    fn find_public_key(
        &self,
        _query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Box<dyn native_pkcs11_traits::PublicKey>>> {
        Ok(None)
    }

    fn find_all_private_keys(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<Arc<dyn native_pkcs11_traits::PrivateKey>>> {
        Ok(vec![])
    }

    fn find_all_public_keys(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<Arc<dyn native_pkcs11_traits::PublicKey>>> {
        Ok(vec![])
    }

    fn generate_key(
        &self,
        _algorithm: native_pkcs11_traits::KeyAlgorithm,
        _label: Option<&str>,
    ) -> native_pkcs11_traits::Result<Arc<dyn native_pkcs11_traits::PrivateKey>> {
        Err("")?
    }

    fn name(&self) -> String {
        "Windows CNG".into()
    }
}

#[derive(Debug)]
pub struct WindowsCertificate {}

impl native_pkcs11_traits::Certificate for WindowsCertificate {
    fn id(&self) -> Vec<u8> {
        todo!()
    }

    fn label(&self) -> String {
        todo!()
    }

    fn to_der(&self) -> Vec<u8> {
        todo!()
    }

    fn public_key(&self) -> &dyn native_pkcs11_traits::PublicKey {
        todo!()
    }

    fn delete(self: Box<Self>) {
        todo!()
    }
}

#[test]
fn backend() {
    native_pkcs11_traits::backend();
}

#[cfg(test)]
mod test {
    use native_pkcs11_traits::random_label;
    use windows::Security::Cryptography::Core::{
        AsymmetricAlgorithmNames,
        AsymmetricKeyAlgorithmProvider,
        CryptographicEngine,
    };

    use super::*;

    #[test]
    fn keygen() -> native_pkcs11_traits::Result<()> {
        let ecdsa = AsymmetricAlgorithmNames::EcdsaP256Sha256()?;
        let key_provider = AsymmetricKeyAlgorithmProvider::OpenAlgorithm(&ecdsa)?;
        let key_pair = key_provider.CreateKeyPair(256)?;

        let payload = random_label();
        let payload = Bytes::from(payload.as_bytes());

        let sig = CryptographicEngine::Sign(&key_pair, &payload.as_buffer_ref()).unwrap();
        Ok(())
    }
}
