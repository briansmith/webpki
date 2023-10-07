// Copyright 2015 Brian Smith.
// Portions Copyright 2033 Daniel McCarney.
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

use crate::ErrorExt;

pub(super) struct Budget {
    signatures: usize,
    build_chain_calls: usize,
}

impl Budget {
    #[inline]
    pub fn consume_signature(&mut self) -> Result<(), ErrorExt> {
        checked_sub(
            &mut self.signatures,
            ErrorExt::MaximumSignatureChecksExceeded,
        )
    }

    #[inline]
    pub fn consume_build_chain_call(&mut self) -> Result<(), ErrorExt> {
        checked_sub(
            &mut self.build_chain_calls,
            ErrorExt::MaximumPathBuildCallsExceeded,
        )
    }
}

fn checked_sub(value: &mut usize, underflow_error: ErrorExt) -> Result<(), ErrorExt> {
    *value = value.checked_sub(1).ok_or(underflow_error)?;
    Ok(())
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            // This limit is taken from the remediation for golang CVE-2018-16875.  However,
            // note that golang subsequently implemented AKID matching due to this limit
            // being hit in real applications (see <https://github.com/spiffe/spire/issues/1004>).
            // So this may actually be too aggressive.
            signatures: 100,

            // This limit is taken from mozilla::pkix, see:
            // <https://github.com/nss-dev/nss/blob/bb4a1d38dd9e92923525ac6b5ed0288479f3f3fc/lib/mozpkix/lib/pkixbuild.cpp#L381-L393>
            build_chain_calls: 200_000,
        }
    }
}
