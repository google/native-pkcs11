# `native-pkcs11`

> pkcs11 module for native credential stores

`native-pkcs11` is a crate for building PKCS#11 modules. Its primary use-case is
authenticating with client certificates. `native-pkcs11` aims to support native
certificate stores (MacOS Keychain, Windows Platform Key Provider) out of the
box. It can also be extended with a custom backend (see
[this section](#building-a-custom-backend)).

## Host Software Compatibility

Software compatibility is a core goal of `native-pkcs11`. It is currently tested
with

- openssh
- openvpn
- Chrome
- Firefox

If a `native-pkcs11` module does not work for your software, please file an
issue.

## Building a Custom Backend

The `native_pkcs11_traits::Backend` trait can be implemented to add support for
a new credential store. Backends are registered in the exported
`C_GetFunctionList` function. In order to register your own backend, enable the
`custom-function-list` feature on `native-pkcs11` and export the method from
your crate. For example:

```rs
use native_pkcs11::{CKR_OK, CK_FUNCTION_LIST_PTR_PTR, CK_RV, FUNC_LIST};
#[no_mangle]
pub extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    // add the custom backend
    native_pkcs11_traits::register_backend(Box::new(backend::MyBackend {}));
    // map this function to the native-pkcs11 function list C_GetFunctionList
    FUNC_LIST.C_GetFunctionList = Some(C_GetFunctionList);
    // assign the result to the output parameter
    unsafe { *ppFunctionList = &mut FUNC_LIST };
    return CKR_OK;
}
```

## Releasing

The [`cargo-ws`](https://github.com/pksunkara/cargo-workspaces) tool can be used
to version bump and release all crates in the workspace at once. It can be
installed with `cargo install cargo-workspaces`.

```bash
# Bump the version of all crates in the workspace
cargo ws version --no-git-push
# Publish all crates to crates.io
cargo ws publish --no-git-push
```
