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

use std::{
    collections::HashMap,
    sync::{self, atomic::Ordering, Arc},
};

use lazy_static::lazy_static;
use native_pkcs11_traits::{PrivateKey, SignatureAlgorithm};
use pkcs11_sys::{CK_FLAGS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE};

use crate::object_store::ObjectStore;

// "Valid session handles in Cryptoki always have nonzero values."
#[cfg(not(target_os = "windows"))]
static NEXT_SESSION_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
#[cfg(target_os = "windows")]
static NEXT_SESSION_HANDLE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

type SessionMap = HashMap<CK_SESSION_HANDLE, Session>;

lazy_static! {
    static ref SESSIONS: sync::Mutex<SessionMap> = Default::default();
    pub static ref OBJECT_STORE: sync::Mutex<ObjectStore> = Default::default();
}

#[derive(Debug)]
pub struct FindContext {
    pub objects: Vec<CK_OBJECT_HANDLE>,
}

#[derive(Debug)]
pub struct SignContext {
    pub algorithm: SignatureAlgorithm,
    pub private_key: Arc<dyn PrivateKey>,
}

#[derive(Default)]
pub struct Session {
    flags: CK_FLAGS,
    pub find_ctx: Option<FindContext>,
    pub sign_ctx: Option<SignContext>,
}

pub fn create(flags: CK_FLAGS) -> CK_SESSION_HANDLE {
    let handle = NEXT_SESSION_HANDLE.fetch_add(1, Ordering::SeqCst);
    SESSIONS.lock().unwrap().insert(
        handle,
        Session {
            flags,
            ..Default::default()
        },
    );
    handle
}

pub fn exists(handle: CK_SESSION_HANDLE) -> bool {
    SESSIONS.lock().unwrap().contains_key(&handle)
}

pub fn flags(handle: CK_SESSION_HANDLE) -> CK_FLAGS {
    SESSIONS.lock().unwrap().get(&handle).unwrap().flags
}

pub fn session<F>(h: CK_SESSION_HANDLE, callback: F) -> crate::Result
where
    F: FnOnce(&mut Session) -> crate::Result,
{
    let mut session_map = SESSIONS.lock().unwrap();
    let session = &mut session_map.get_mut(&h).unwrap();
    callback(session)
}

pub fn close(handle: CK_SESSION_HANDLE) -> bool {
    SESSIONS.lock().unwrap().remove(&handle).is_some()
}

pub fn close_all() {
    SESSIONS.lock().unwrap().clear()
}
