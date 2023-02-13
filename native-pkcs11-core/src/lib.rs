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

use attribute::AttributeType;
use pkcs11_sys::*;
use thiserror::Error;

pub mod attribute;
pub mod mechanism;
pub mod object;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    // Cryptoki errors.
    #[error("arguments bad")]
    ArgumentsBad,

    #[error("{0} is not a valid attribute type")]
    AttributeTypeInvalid(CK_ATTRIBUTE_TYPE),

    #[error("the value for attribute {0} is invalid")]
    AttributeValueInvalid(AttributeType),

    #[error("buffer too small")]
    BufferTooSmall,

    #[error("cryptoki module has already been initialized")]
    CryptokiAlreadyInitialized,

    #[error("cryptoki module has not been initialized")]
    CryptokiNotInitialized,

    #[error("function not parallel")]
    FunctionNotParallel,

    #[error("function not supported")]
    FunctionNotSupported,

    #[error("key handle {0} is invalid")]
    KeyHandleInvalid(CK_OBJECT_HANDLE),

    #[error("module cannot function without being able to spawn threads")]
    NeedToCreateThreads,

    #[error("{0} is not a valid mechanism")]
    MechanismInvalid(CK_MECHANISM_TYPE),

    #[error("object {0} is invalid")]
    ObjectHandleInvalid(CK_OBJECT_HANDLE),

    #[error("operation has not been initialized")]
    OperationNotInitialized,

    #[error("no random number generator")]
    RandomNoRng,

    #[error("session handle {0} is invalid")]
    SessionHandleInvalid(CK_SESSION_HANDLE),

    #[error("token does not support parallel sessions")]
    SessionParallelNotSupported,

    #[error("slot id {0} is invalid")]
    SlotIdInvalid(CK_SLOT_ID),

    #[error("token is write protected")]
    TokenWriteProtected,

    // Other errors.
    #[error("{0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    #[error("{0}")]
    FromVecWithNul(#[from] std::ffi::FromVecWithNulError),

    #[error("null pointer error")]
    NullPtr,

    #[cfg(target_os = "macos")]
    #[error("{0}")]
    Pkcs11Keychain(#[from] native_pkcs11_keychain::Error),

    #[error("{0}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("{0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    // Catch-all for backend-related errors.
    #[error("{0}")]
    Backend(#[from] Box<dyn std::error::Error>),

    #[error("{0}")]
    Todo(String),
}

impl From<Error> for CK_RV {
    fn from(e: Error) -> Self {
        match e {
            Error::ArgumentsBad => CKR_ARGUMENTS_BAD,
            Error::AttributeTypeInvalid(_) => CKR_ATTRIBUTE_TYPE_INVALID,
            Error::AttributeValueInvalid(_) => CKR_ATTRIBUTE_VALUE_INVALID,
            Error::BufferTooSmall => CKR_BUFFER_TOO_SMALL,
            Error::CryptokiAlreadyInitialized => CKR_CRYPTOKI_ALREADY_INITIALIZED,
            Error::CryptokiNotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED,
            Error::FunctionNotParallel => CKR_FUNCTION_NOT_PARALLEL,
            Error::FunctionNotSupported => CKR_FUNCTION_NOT_SUPPORTED,
            Error::KeyHandleInvalid(_) => CKR_KEY_HANDLE_INVALID,
            Error::MechanismInvalid(_) => CKR_MECHANISM_INVALID,
            Error::NeedToCreateThreads => CKR_NEED_TO_CREATE_THREADS,
            Error::ObjectHandleInvalid(_) => CKR_OBJECT_HANDLE_INVALID,
            Error::OperationNotInitialized => CKR_OPERATION_NOT_INITIALIZED,
            Error::RandomNoRng => CKR_RANDOM_NO_RNG,
            Error::SessionHandleInvalid(_) => CKR_SESSION_HANDLE_INVALID,
            Error::SessionParallelNotSupported => CKR_SESSION_PARALLEL_NOT_SUPPORTED,
            Error::SlotIdInvalid(_) => CKR_SLOT_ID_INVALID,
            Error::TokenWriteProtected => CKR_TOKEN_WRITE_PROTECTED,

            Error::Backend(_)
            | Error::FromUtf8(_)
            | Error::FromVecWithNul(_)
            | Error::NullPtr
            | Error::Todo(_)
            | Error::TryFromInt(_)
            | Error::TryFromSlice(_) => CKR_GENERAL_ERROR,

            #[cfg(target_os = "macos")]
            Error::Pkcs11Keychain(_) => CKR_GENERAL_ERROR,
        }
    }
}
