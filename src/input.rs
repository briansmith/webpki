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

/// Calls `read` with the given input as a `Reader`, ensuring that `read`
/// consumed the entire input. If `read` does not consume the entire input,
/// `incomplete_read` is returned.
pub fn read_all<'a, F, R, E>(input: Input<'a>, incomplete_read: E, read: F)
                             -> Result<R, E>
                             where F: FnOnce(&mut Reader<'a>) -> Result<R, E> {
    let mut input = Reader::new(input);
    let result = try!(read(&mut input));
    if input.at_end() {
        Ok(result)
    } else {
        Err(incomplete_read)
    }
}

/// Like `read_all`, except taking an `FnMut`.
pub fn read_all_mut<'a, F, R, E>(input: Input<'a>, incomplete_read: E, mut read: F)
                                 -> Result<R, E>
                                 where F: FnMut(&mut Reader<'a>)
                                                -> Result<R, E> {
    let mut input = Reader::new(input);
    let result = try!(read(&mut input));
    if input.at_end() {
        Ok(result)
    } else {
        Err(incomplete_read)
    }
}


/// Calls `read` with the given input as a `Reader`, ensuring that `read`
/// consumed the entire input. When `input` is `None`, `read` will be called
/// with `None`.
pub fn read_all_optional<'a, F, R, E>(input: Option<Input<'a>>,
                                      incomplete_read: E, read: F)
                                      -> Result<R, E>
                                      where F: FnOnce(Option<&mut Reader>)
                                                      -> Result<R, E> {
    match input {
        Some(input) => {
            let mut input = Reader::new(input);
            let result = try!(read(Option::Some(&mut input)));
            if input.at_end() {
                Ok(result)
            } else {
                Err(incomplete_read)
            }
        },
        None => read(Option::None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Input<'a> {
    bytes: &'a [u8]
}

impl<'a> Input<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Input<'a>> {
        // This limit is important for avoiding integer overflow. In particular,
        // `Reader` assumes that an `i + 1 > i` if `input.bytes.get(i)` does
        // not return `None`.
        if bytes.len() > 0xFFFF {
            return None
        }
        Some(Input { bytes: bytes })
    }

    pub fn as_slice_less_safe(&self) -> &[u8] { self.bytes }

    pub fn is_empty(&self) -> bool { self.bytes.len() == 0 }

    pub fn len(&self) -> usize { self.bytes.len() }
}

pub fn input_equals(a: Input, b: &[u8]) -> bool { a.bytes == b }

#[derive(Debug)]
pub struct Reader<'a> {
    input: Input<'a>,
    i: usize
}

pub struct Mark {
    i: usize
}

impl<'a> Reader<'a> {
    pub fn new(input: Input<'a>) -> Reader<'a> {
        Reader {
            input: input,
            i: 0
        }
    }

    pub fn at_end(&self) -> bool { self.i == self.input.bytes.len() }

    pub fn get_input_between_marks(&self, mark1: Mark, mark2: Mark)
                                   -> Option<Input<'a>> {
        Some(Input { bytes: &self.input.bytes[mark1.i..mark2.i] })
    }

    pub fn mark(&self) -> Mark {
        Mark { i: self.i }
    }

    pub fn peek(&self, b: u8) -> bool {
        match self.input.bytes.get(self.i) {
            Some(actual_b) => return b == *actual_b,
            None => false
        }
    }

    pub fn read_byte(&mut self) -> Option<u8> {
        match self.input.bytes.get(self.i) {
            Some(b) => {
                self.i += 1; // safe from overflow; see Input::new.
                Some(*b)
            }
            None => None
        }
    }

    pub fn skip_and_get_input(&mut self, num_bytes: usize)
                              -> Option<Input<'a>> {
        match self.i.checked_add(num_bytes) {
            Some(new_i) if new_i <= self.input.bytes.len() => {
                let ret =
                    Some(Input { bytes: &self.input.bytes[self.i..new_i] });
                self.i = new_i;
                ret
            },
            _ => None
        }
    }

    pub fn skip_to_end(&mut self) -> Input<'a> {
        let result = Input { bytes: &self.input.bytes[self.i..] };
        self.i = self.input.bytes.len();
        result
    }
}
