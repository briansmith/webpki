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

const CONSTRUCTED : u8 = 1 << 5;
const CONTEXT_SPECIFIC : u8 = 2 << 6;

#[derive(PartialEq)]
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

pub fn null(input: &mut Reader) -> Result<(), Error> {
    let contents = try!(expect_tag_and_get_input(input, Tag::Null));
    if !contents.is_empty() {
        return Err(Error::BadDER);
    }
    Ok(())
}

pub fn optional_null(input: &mut Reader) -> Result<(), Error> {
    if !input.peek(Tag::Null as u8) {
        return Ok(());
    }
    null(input)
}
