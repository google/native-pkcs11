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

The `pkcs11_traits::Backend` trait can be implemented to add support for a new
credential store. The [`inventory`](https://crates.io/inventory) crate is used
to register Backend implementations a build time. This allows backends to be
registered without being a direct dependency of the `native-pkcs11` crate.
