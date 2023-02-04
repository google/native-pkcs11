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

use std::fmt::Debug;

pub use backend::KeychainBackend;
use core_foundation::error::CFError;
use native_pkcs11_traits::{once_cell::sync::Lazy, Backend, RegisteredBackend};
use thiserror::Error;
use tracing_error::SpanTrace;

mod backend;
pub mod certificate;
pub mod key;

static BACKEND: Lazy<Box<dyn Backend>> = Lazy::new(|| Box::new(KeychainBackend::new()));

native_pkcs11_traits::inventory::submit! {RegisteredBackend(&BACKEND)}

//  NOTE(kcking): I think this just works because any non-System path defaults
//  to the Login keychain
pub const LOGIN_KEYCHAIN_PATH: &str = "login.keychain";
pub const SYSTEM_KEYCHAIN_PATH: &str = "/Library/Keychains/System.keychain";

pub type Result<T> = std::result::Result<T, Error>;

pub struct Error {
    error: ErrorKind,
    context: SpanTrace,
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self.error)?;
        self.context.fmt(f)
    }
}

impl std::error::Error for Error {}

impl<E: Into<ErrorKind>> From<E> for Error {
    fn from(e: E) -> Self {
        Error {
            error: e.into(),
            context: SpanTrace::capture(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.error)?;
        std::fmt::Display::fmt(&self.context, f)
    }
}

#[derive(Error, Debug)]
pub enum ErrorKind {
    #[error("GenericError {0}")]
    Generic(String),

    #[error("{0}")]
    Der(#[from] der::Error),

    #[error("{0}")]
    SecurityFramework(#[from] security_framework::base::Error),

    #[error("{0}")]
    Spki(#[from] spki::Error),

    #[error("{0}")]
    P256(#[from] p256::elliptic_curve::Error),

    #[error("{0}")]
    Pkcs1(#[from] pkcs1::Error),
}

impl From<CFError> for ErrorKind {
    fn from(e: CFError) -> Self {
        ErrorKind::SecurityFramework(security_framework::base::Error::from_code(e.code() as i32))
    }
}

impl From<&str> for ErrorKind {
    fn from(s: &str) -> Self {
        ErrorKind::Generic(s.to_string())
    }
}

impl From<String> for ErrorKind {
    fn from(s: String) -> Self {
        ErrorKind::Generic(s)
    }
}
