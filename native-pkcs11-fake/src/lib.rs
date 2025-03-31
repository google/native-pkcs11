use std::ptr::addr_of_mut;

use native_pkcs11::{CKR_OK, CK_FUNCTION_LIST_PTR_PTR, CK_RV, FUNC_LIST};
use native_pkcs11_traits::{register_backend, Backend};

#[allow(non_snake_case)]
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    register_backend(Box::new(FakeBackend {}));
    unsafe { *ppFunctionList = addr_of_mut!(FUNC_LIST) };
    CKR_OK
}

struct FakeBackend {}

impl Backend for FakeBackend {
    fn name(&self) -> String {
        todo!()
    }

    fn find_all_certificates(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<Box<dyn native_pkcs11_traits::Certificate>>> {
        todo!()
    }

    fn find_private_key(
        &self,
        _query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<std::sync::Arc<dyn native_pkcs11_traits::PrivateKey>>>
    {
        todo!()
    }

    fn find_public_key(
        &self,
        _query: native_pkcs11_traits::KeySearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Box<dyn native_pkcs11_traits::PublicKey>>> {
        todo!()
    }

    fn find_all_private_keys(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<std::sync::Arc<dyn native_pkcs11_traits::PrivateKey>>>
    {
        todo!()
    }

    fn find_all_public_keys(
        &self,
    ) -> native_pkcs11_traits::Result<Vec<std::sync::Arc<dyn native_pkcs11_traits::PublicKey>>>
    {
        todo!()
    }

    fn generate_key(
        &self,
        _algorithm: native_pkcs11_traits::KeyAlgorithm,
        _label: Option<&str>,
    ) -> native_pkcs11_traits::Result<std::sync::Arc<dyn native_pkcs11_traits::PrivateKey>> {
        todo!()
    }
}
