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

use std::io::Write;

pub fn right_pad_string_to_array<const N: usize>(s: impl Into<String>) -> [u8; N] {
    let mut s: String = s.into();
    let new_len = (0..=N).rev().find(|idx| s.is_char_boundary(*idx)).unwrap_or(0);
    s.truncate(new_len);

    let mut out = [b' '; N];
    let _ = out.as_mut_slice().write_all(s.as_bytes());

    out
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn string_padding() {
        assert_eq!(right_pad_string_to_array::<4>("asd"), *b"asd ");
        assert_eq!(right_pad_string_to_array::<3>("asd"), *b"asd");
        assert_eq!(right_pad_string_to_array::<2>("asd"), *b"as");
        assert_eq!(
            right_pad_string_to_array::<5>("🧑‍🔬"),
            //  Utf-8 encoding of "person" followed by a space.
            [0xF0, 0x9F, 0xA7, 0x91, b' ']
        );
    }
}
