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

use ring;
pub use ring::der::{
    CONSTRUCTED,

    Tag,

    nested,
};
use super::Error;
use time::{Timespec, Tm};
use untrusted;

// TODO: Get rid of this. This is just here to make it easier to adapt to the
// movement of the core DER functionality from webpki to *ring*.
#[inline(always)]
pub fn expect_tag_and_get_input<'a>(input: &mut untrusted::Reader<'a>,
                                    tag: Tag) ->
                                    Result<untrusted::Input<'a>, Error> {
    ring::der::expect_tag_and_get_value(input, tag).map_err(|_| Error::BadDER)
}

// TODO: Get rid of this. This is just here to make it easier to adapt to the
// movement of the core DER functionality from webpki to *ring*.
#[inline(always)]
pub fn read_tag_and_get_input<'a>(input: &mut untrusted::Reader<'a>)
                                  -> Result<(u8, untrusted::Input<'a>), Error> {
    ring::der::read_tag_and_get_value(input).map_err(|_| Error::BadDER)
}

// TODO: investigate taking decoder as a reference to reduce generated code
// size.
#[inline(always)]
pub fn nested_mut<'a, F, R, E: Copy>(input: &mut untrusted::Reader<'a>,
                                     tag: Tag, error: E, decoder: F)
                                     -> Result<R, E>
                                     where F : FnMut(&mut untrusted::Reader<'a>)
                                                     -> Result<R, E> {
    let inner = try!(expect_tag_and_get_input(input, tag).map_err(|_| error));
    inner.read_all_mut(error, decoder).map_err(|_| error)
}

// TODO: investigate taking decoder as a reference to reduce generated code
// size.
pub fn nested_of_mut<'a, F, E: Copy>(input: &mut untrusted::Reader<'a>,
                                     outer_tag: Tag, inner_tag: Tag, error: E,
                                     mut decoder: F) -> Result<(), E>
                                     where F : FnMut(&mut untrusted::Reader<'a>)
                                                     -> Result<(), E> {
    nested_mut(input, outer_tag, error, |outer| {
        loop {
            try!(nested_mut(outer, inner_tag, error, |inner| decoder(inner)));
            if outer.at_end() {
                break;
            }
        }
        Ok(())
    })
}

pub fn bit_string_with_no_unused_bits<'a>(input: &mut untrusted::Reader<'a>)
                                          -> Result<untrusted::Input<'a>,
                                                    Error> {
    nested(input, Tag::BitString, Error::BadDER, |value| {
        let unused_bits_at_end =
            try!(value.read_byte().map_err(|_| Error::BadDER));
        if unused_bits_at_end != 0 {
            return Err(Error::BadDER);
        }
        Ok(value.skip_to_end())
    })
}

// Like mozilla::pkix, we accept the the non-conformant explicit encoding of
// the default value (false) for compatibility with real-world certificates.
pub fn optional_boolean(input: &mut untrusted::Reader) -> Result<bool, Error> {
    if !input.peek(Tag::Boolean as u8) {
        return Ok(false);
    }
    nested(input, Tag::Boolean, Error::BadDER, |input| {
        match input.read_byte() {
            Ok(0xff) => Ok(true),
            Ok(0x00) => Ok(false),
            _ => Err(Error::BadDER)
        }
    })
}

pub fn positive_integer<'a>(input: &'a mut untrusted::Reader)
                            -> Result<untrusted::Input<'a>, Error> {
    ring::der::positive_integer(input).map_err(|_| Error::BadDER)
}

pub fn small_nonnegative_integer<'a>(input: &'a mut untrusted::Reader)
                                     -> Result<u8, Error> {
    ring::der::small_nonnegative_integer(input).map_err(|_| Error::BadDER)
}


pub fn null(input: &mut untrusted::Reader) -> Result<(), Error> {
    nested(input, Tag::Null, Error::BadDER, |_| Ok(()))
}

pub fn time_choice<'a>(input: &mut untrusted::Reader<'a>)
                       -> Result<Timespec, Error> {
    let is_utc_time = input.peek(Tag::UTCTime as u8);
    let expected_tag = if is_utc_time { Tag::UTCTime }
                       else { Tag::GeneralizedTime };

    fn read_digit(inner: &mut untrusted::Reader) -> Result<i32, Error> {
        let b = try!(inner.read_byte().map_err(|_| Error::BadDERTime));
        if b < b'0' || b > b'9' {
            return Err(Error::BadDERTime);
        }
        Ok((b - b'0') as i32)
    }

    fn read_two_digits(inner: &mut untrusted::Reader, min: i32, max: i32)
                       -> Result<i32, Error> {
        let hi = try!(read_digit(inner));
        let lo = try!(read_digit(inner));
        let value = (hi * 10) + lo;
        if value < min || value > max {
            return Err(Error::BadDERTime);
        }
        Ok(value)
    }

    nested(input, expected_tag, Error::BadDER, |value| {
        let (year_hi, year_lo) =
            if is_utc_time {
                let lo = try!(read_two_digits(value, 0, 99));
                let hi = if lo >= 50 { 19 } else { 20 };
                (hi, lo)
            } else {
                let hi = try!(read_two_digits(value, 0, 99));
                let lo = try!(read_two_digits(value, 0, 99));
                (hi, lo)
            };

        let year = (year_hi * 100) + year_lo;
        // We don't support dates before January 1, 1970 because that is the
        // Unix epoch. It is likely that other software won't deal well with
        // certificates that have dates before the epoch.
        if year < 1970 {
            return Err(Error::BadDERTime);
        }

        let month = try!(read_two_digits(value, 1, 12));
        let days_in_month = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 =>
                if (year % 4 == 0) &&
                    ((year % 100 != 0) || (year % 400 == 0)) {
                    29
                } else {
                    28
                },
            _ => unreachable!() // `read_two_digits` already bounds-checked it.
        };

        let day_of_month = try!(read_two_digits(value, 1, days_in_month));
        let hours = try!(read_two_digits(value, 0, 23));
        let minutes = try!(read_two_digits(value, 0, 59));
        let seconds = try!(read_two_digits(value, 0, 59));

        let time_zone = try!(value.read_byte().map_err(|_| Error::BadDERTime));
        if time_zone != b'Z' {
            return Err(Error::BadDERTime);
        }

        // XXX: We need to audit the `time` crate for correctness.
        let tm = Tm {
            tm_year: year - 1900,
            tm_mon: month - 1,
            tm_mday: day_of_month,
            tm_hour: hours,
            tm_min: minutes,
            tm_sec: seconds,
            tm_nsec: 0,

            // These should all be ignored by `to_timespec`.
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_utcoff: 0,
        };

        Ok(tm.to_timespec())
    })
}

macro_rules! oid {
    ( $first:expr, $second:expr, $( $tail:expr ),* ) =>
    (
        [(40 * $first) + $second, $( $tail ),*]
    )
}

macro_rules! oid_1_2_840_10045 {
   ( $( $tail:expr ),* ) =>
   (
        oid![1, 2,
             0x86, 0x48, // 840
             0xce, 0x3d, // 10045
             $( $tail ),*]
   )
}

macro_rules! oid_1_2_840_113549 {
    ( $( $tail:expr ),* ) =>
    (
        oid![1, 2,
             0x86, 0x48, // 840
             0x86, 0xf7, 0x0d, // 113549
             $( $tail ),* ]
    )
}

macro_rules! oid_1_3_132 {
    ( $( $tail:expr ),* ) =>
    (
        oid![1, 3,
             0x81, 0x04, // 132
             $( $tail ),* ]
    )
}
