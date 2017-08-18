// Copyright 2015-2016 Brian Smith.
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

//! Conversions into the library's time type.

/// The time type.
///
/// Internally this is merely a UNIX timestamp: a count of non-leap
/// seconds since the start of 1970.  This type exists to assist
/// unit-of-measure correctness.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Time(u64);

#[cfg(feature = "std")]
pub mod stdsupport {
    use std::time;
    use std::convert;
    use super::Time;

    impl convert::From<time::SystemTime> for Time {
        fn from(st: time::SystemTime) -> Time {
            Time(st.duration_since(time::UNIX_EPOCH)
                 .unwrap() // it's definitely after 1970 now
                 .as_secs())
        }
    }
}

impl Time {
    /// Create a `webpki::Time` from a unix timestamp.
    pub fn from_seconds_from_unix_epoch(secs: u64) -> Time {
        Time(secs)
    }
}
