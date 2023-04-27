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

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::slice;

#[cfg(target_os = "windows")]
mod pkcs11_windows;
#[cfg(target_os = "windows")]
pub use pkcs11_windows::*;

#[cfg(target_os = "windows")]
pub const CK_UNAVAILABLE_INFORMATION: u32 = std::u32::MAX;

#[cfg(not(target_os = "windows"))]
include!("pkcs11_unix.rs");

pub struct Attribute<'a>(&'a mut CK_ATTRIBUTE);

impl Attribute<'_> {
    pub fn from(attribute: &mut CK_ATTRIBUTE) -> Attribute {
        Attribute(attribute)
    }

    pub fn type_(&self) -> CK_ATTRIBUTE_TYPE {
        self.0.type_
    }

    pub fn value(&self) -> &[u8] {
        if self.0.pValue.is_null() {
            todo!();
        }
        unsafe {
            slice::from_raw_parts(
                self.0.pValue as *const u8,
                self.0.ulValueLen.try_into().unwrap(),
            )
        }
    }

    pub fn set_value(&mut self, value: Vec<u8>) {
        if self.0.pValue.is_null() {
            self.0.ulValueLen = value.len() as CK_ULONG;
            return;
        }
        if (self.0.ulValueLen as usize) < value.len() {
            self.0.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return;
        }
        unsafe { slice::from_raw_parts_mut(self.0.pValue as *mut u8, value.len()) }
            .copy_from_slice(&value);
        self.0.ulValueLen = value.len() as CK_ULONG;
    }

    pub fn set_unavailable(&mut self) {
        self.0.ulValueLen = CK_UNAVAILABLE_INFORMATION;
    }
}

pub struct Attributes<'a> {
    pub attributes: Vec<Attribute<'a>>,
}

impl<'a> Attributes<'a> {
    pub fn new(attributes: Vec<Attribute<'a>>) -> Self {
        Self { attributes }
    }

    pub fn from_raw_parts(ptr: *mut CK_ATTRIBUTE, len: usize) -> Attributes<'a> {
        if ptr.is_null() {
            todo!();
        }
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
        let attributes = slice
            .iter_mut()
            .map(|attr| Attribute(attr))
            .collect::<Vec<_>>();

        Self::new(attributes)
    }
}
