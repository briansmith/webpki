// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Utilities for efficiently embedding trust anchors in programs.

use crate::TrustAnchor;
use alloc::string::String;

/// Generates code for hard-coding the given trust anchors into a program. This
/// is designed to be used in a build script. `name` is the name of the public
/// static variable that will contain the TrustAnchor array.
///
/// Requires the `alloc` feature.
pub fn generate_code_for_trust_anchors(name: &str, trust_anchors: &[TrustAnchor]) -> String {
    let decl = format!(
        "static {}: [TrustAnchor<'static>; {}] = ",
        name,
        trust_anchors.len()
    );

    // "{:?}" formats the array of trust anchors as Rust code, approximately,
    // except that it drops the leading "&" on slices.
    let value = str::replace(&format!("{:?};\n", trust_anchors), ": [", ": &[");

    decl + &value
}
