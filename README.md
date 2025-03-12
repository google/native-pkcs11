# native-pkcs11

> pkcs11 module for native credential stores

`native-pkcs11` is a crate for building PKCS#11 modules. Its primary use-case is
authenticating with client certificates. `native-pkcs11` aims to support native
certificate stores (MacOS Keychain, Windows Platform Key Provider) out of the
box. It can also be extended with a custom backend (see
[this section](#building-a-custom-backend)).

## Features

*   **Native Credential Store Support:** `native-pkcs11` seamlessly integrates with native credential stores like the macOS Keychain and Windows Platform Key Provider.
*   **Extensible Architecture:** Add support for custom credential stores by implementing the `native_pkcs11_traits::Backend` trait.
*   **Broad Compatibility:** Tested and compatible with OpenSSH, OpenVPN, Chrome, and Firefox.
* **Java support:** This library can also be used with java. The `tests/java/SunPKCS11ProviderTest.java` has a test case for that.

## Getting Started

### Installation

To use `native-pkcs11`, you'll need to build the library from source.

1.  **Clone the Repository:** Clone the `native-pkcs11` repository to your local machine.
2.  **Build:** Build the library with `cargo build`.

### Usage

#### macOS

1.  **Create a Keychain:** Create a temporary keychain using the `tests/create_keychain.sh` script.
2.  **Set Environment Variable:** Set the `NATIVE_PKCS11_KEYCHAIN_PATH` environment variable to the path of your keychain.
3.  **Run:** Run `cargo test`.

#### Windows

Support for Windows is currently under development.

#### Java

1. **Install:**  Install the `SunPKCS11Provider` following the instructions on this page: [https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html](https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html)
2. **Configure:** Configure the SunPKCS11Provider using the `tests/java/SunPKCS11ProviderTest.java` as an example.
3. **Run:** Run the tests using the `tests/java/run.sh` script.

## Building a Custom Backend

The `native_pkcs11_traits::Backend` trait can be implemented to add support for
a new credential store. Backends are registered in the exported
`C_GetFunctionList` function. In order to register your own backend, enable the
`custom-function-list` feature on `native-pkcs11` and export the method from
your crate. For example:
