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

use super::Error;
use super::input::*;
use time::{Timespec, Tm};

pub const CONSTRUCTED : u8 = 1 << 5;
pub const CONTEXT_SPECIFIC : u8 = 2 << 6;

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Tag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    OID = 0x06,
    Sequence = CONSTRUCTED | 0x10, // 0x30
    UTCTime = 0x17,
    GeneralizedTime = 0x18,

    ContextSpecificConstructed0 = CONTEXT_SPECIFIC | CONSTRUCTED | 0,
    ContextSpecificConstructed1 = CONTEXT_SPECIFIC | CONSTRUCTED | 1,
    ContextSpecificConstructed3 = CONTEXT_SPECIFIC | CONSTRUCTED | 3,
}

pub fn expect_tag_and_get_input<'a>(input: &mut Reader<'a>, tag: Tag)
                                    -> Result<Input<'a>, Error> {
    let (actual_tag, inner) = try!(read_tag_and_get_input(input));
    if (tag as usize) != (actual_tag as usize) {
        return Err(Error::BadDER);
    }
    Ok(inner)
}

fn read_tag_and_get_input<'a>(input: &mut Reader<'a>)
                              -> Result<(u8, Input<'a>), Error> {
    let tag = try!(input.read_byte().ok_or(Error::BadDER));
    if (tag & 0x1F) == 0x1F {
        return Err(Error::BadDER) // High tag number form is not allowed.
    }

    // If the high order bit of the first byte is set to zero then the length
    // is encoded in the seven remaining bits of that byte. Otherwise, those
    // seven bits represent the number of bytes used to encode the length.
    let length = match try!(input.read_byte().ok_or(Error::BadDER)) {
        n if (n & 0x80) == 0 => n as usize,
        0x81 => {
            let second_byte = try!(input.read_byte().ok_or(Error::BadDER));
            if second_byte < 128 {
                return Err(Error::BadDER) // Not the canonical encoding.
            }
            second_byte as usize
        },
        0x82 => {
            let second_byte = try!(input.read_byte().ok_or(Error::BadDER))
                              as usize;
            let third_byte = try!(input.read_byte().ok_or(Error::BadDER))
                             as usize;
            let combined = (second_byte << 8) | third_byte;
            if combined < 256 {
                return Err(Error::BadDER); // Not the canonical encoding.
            }
            combined
        },
        _ => {
            return Err(Error::BadDER); // We don't support longer lengths.
        }
    };

    let inner = try!(input.skip_and_get_input(length).ok_or(Error::BadDER));
    Ok((tag, inner))
}

// TODO: investigate taking decoder as a reference to reduce generated code
// size.
pub fn nested<'a, F, R>(input: &mut Reader<'a>, tag: Tag, decoder: F)
                        -> Result<R, Error>
                        where F : FnOnce(&mut Reader<'a>) -> Result<R, Error> {
    let inner = try!(expect_tag_and_get_input(input, tag));
    read_all(inner, Error::BadDER, decoder)
}

// TODO: investigate taking decoder as a reference to reduce generated code
// size.
pub fn nested_mut<'a, F, R>(input: &mut Reader<'a>, tag: Tag, decoder: F)
                            -> Result<R, Error>
                            where F : FnMut(&mut Reader<'a>)
                                      -> Result<R, Error> {
    let inner = try!(expect_tag_and_get_input(input, tag));
    read_all_mut(inner, Error::BadDER, decoder)
}

// TODO: investigate taking decoder as a reference to reduce generated code
// size.
pub fn nested_of_mut<'a, F>(input: &mut Reader<'a>, outer_tag: Tag,
                            inner_tag: Tag, mut decoder: F) -> Result<(), Error>
                            where F : FnMut(&mut Reader<'a>)
                                      -> Result<(), Error> {
    nested_mut(input, outer_tag, |outer| {
        loop {
            try!(nested_mut(outer, inner_tag, |inner| decoder(inner)));
            if outer.at_end() {
                break;
            }
        }
        Ok(())
    })
}

pub fn bit_string_with_no_unused_bits<'a>(input: &mut Reader<'a>)
                                          -> Result<Input<'a>, Error> {
    nested(input, Tag::BitString, |value| {
        let unused_bits_at_end = try!(value.read_byte().ok_or(Error::BadDER));
        if unused_bits_at_end != 0 {
            return Err(Error::BadDER);
        }
        Ok(value.skip_to_end())
    })
}

// Like mozilla::pkix, we accept the the non-conformant explicit encoding of
// the default value (false) for compatibility with real-world certificates.
pub fn optional_boolean(input: &mut Reader) -> Result<bool, Error> {
    if !input.peek(Tag::Boolean as u8) {
        return Ok(false);
    }
    nested(input, Tag::Boolean, |input| {
        match input.read_byte() {
            Some(0xff) => Ok(true),
            Some(0x00) => Ok(false),
            _ => Err(Error::BadDER)
        }
    })
}

// This parser will only parse values between 0..127. mozilla::pkix found
// experimentally that the need to parse larger values is not useful.
pub fn integer(input: &mut Reader) -> Result<u8, Error> {
    nested(input, Tag::Integer, |value| {
        let first_byte = try!(value.read_byte().ok_or(Error::BadDER));
        if (first_byte & 0x80) != 0 {
            // We don't accept negative values
            return Err(Error::BadDER);
        }
        Ok(first_byte)
    })
}

pub fn null(input: &mut Reader) -> Result<(), Error> {
    nested(input, Tag::Null, |_| Ok(()))
}

pub fn optional_null(input: &mut Reader) -> Result<(), Error> {
    if !input.peek(Tag::Null as u8) {
        return Ok(());
    }
    null(input)
}

pub fn time_choice<'a>(input: &mut Reader<'a>) -> Result<Timespec, Error> {
    let is_utc_time = input.peek(Tag::UTCTime as u8);
    let expected_tag = if is_utc_time { Tag::UTCTime }
                       else { Tag::GeneralizedTime };

    fn read_digit(inner: &mut Reader) -> Result<i32, Error> {
        let b = try!(inner.read_byte().ok_or(Error::BadDERTime));
        if b < b'0' || b > b'9' {
            return Err(Error::BadDERTime);
        }
        Ok((b - b'0') as i32)
    }

    fn read_two_digits(inner: &mut Reader, min: i32, max: i32)
                       -> Result<i32, Error> {
        let hi = try!(read_digit(inner));
        let lo = try!(read_digit(inner));
        let value = (hi * 10) + lo;
        if value < min || value > max {
            return Err(Error::BadDERTime);
        }
        Ok(value)
    }

    nested(input, expected_tag, |value| {
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

        let time_zone = try!(value.read_byte().ok_or(Error::BadDERTime));
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
