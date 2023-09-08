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

#[cfg(target_os = "macos")]
fn main() -> Result<(), native_pkcs11_keychain::Error> {
    use std::{
        io::Write,
        os::unix::io::{FromRawFd, IntoRawFd},
        process::Stdio,
    };

    use native_pkcs11_keychain::{certificate::self_signed_certificate, key::generate_key, *};

    let key = generate_key(key::Algorithm::RSA, "nativepkcs11test", None)?;
    let cert_der = self_signed_certificate(key::Algorithm::RSA, &key)?;

    let key_der = key.external_representation().unwrap().to_vec();
    std::fs::write("/tmp/importkey.der", &key_der).unwrap();

    //  convert cert to PEM
    let mut child = std::process::Command::new("openssl")
        .args(["x509", "-inform", "DER"])
        .stdin(Stdio::piped())
        .stdout(unsafe {
            Stdio::from_raw_fd(
                std::fs::File::create("/tmp/importcert.pem")
                    .unwrap()
                    .into_raw_fd(),
            )
        })
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&cert_der).unwrap();
    dbg!(child.wait_with_output().unwrap());

    // convert key to PEM
    let child = std::process::Command::new("openssl")
        .args(["rsa", "-inform", "DER", "-in", "/tmp/importkey.der"])
        .stdout(unsafe {
            Stdio::from_raw_fd(
                std::fs::File::create("/tmp/importkey.pem")
                    .unwrap()
                    .into_raw_fd(),
            )
        })
        .spawn()
        .unwrap();
    dbg!(child.wait_with_output().unwrap());

    //  group cert and key into p12 file
    let output = std::process::Command::new("openssl")
        .args([
            "pkcs12",
            "-export",
            "-out",
            "/tmp/import.p12",
            "-inkey",
            "/tmp/importkey.pem",
            "-in",
            "/tmp/importcert.pem",
            "-legacy", /* keychain uses old PBKDF algorithm, default was changed in newer
                        * versions of openssl */
            "-passout",
            "pass:password",
        ])
        .stdout(unsafe {
            Stdio::from_raw_fd(
                std::fs::File::create("/tmp/import.p12")
                    .unwrap()
                    .into_raw_fd(),
            )
        })
        .output()
        .unwrap();
    dbg!(&output);
    //  github runner has older openssl that uses correct algorithm by default
    //  and doesn't have a -legacy flag
    if String::from_utf8_lossy(&output.stderr).contains("Unrecognized flag legacy") {
        let child = std::process::Command::new("openssl")
            .args([
                "pkcs12",
                "-export",
                "-out",
                "/tmp/import.p12",
                "-inkey",
                "/tmp/importkey.pem",
                "-in",
                "/tmp/importcert.pem",
                "-passout",
                "pass:password",
            ])
            .stdout(unsafe {
                Stdio::from_raw_fd(
                    std::fs::File::create("/tmp/import.p12")
                        .unwrap()
                        .into_raw_fd(),
                )
            })
            .spawn()
            .unwrap();
        dbg!(child.wait_with_output().unwrap());
    }

    let child = std::process::Command::new("security")
        .args([
            "import",
            "/tmp/import.p12",
            "-k",
            "nativepkcs11test",
            "-A",
            "-P",
            "password",
        ])
        .spawn()
        .map_err(|e| format!("failed to spawn: {e:?}"))?;
    dbg!(child.wait_with_output().unwrap());

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {}
