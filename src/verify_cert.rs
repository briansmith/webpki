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
use super::cert::EndEntityOrCA;
use super::der;
use super::input::Reader;
use time::Timespec;

// https://tools.ietf.org/html/rfc5280#section-4.1.2.5
fn check_validity(input: &mut Reader, time: Timespec) -> Result<(), Error> {
    let not_before = try!(der::time_choice(input));
    let not_after = try!(der::time_choice(input));

    if not_before > not_after {
        return Err(Error::InvalidCertValidity);
    }
    if time < not_before {
        return Err(Error::CertNotValidYet);
    }
    if time > not_after {
        return Err(Error::CertExpired);
    }

    // TODO: mozilla::pkix allows the TrustDomain to check not_before and
    // not_after, to enforce things like a maximum validity period. We should
    // do something similar.

    Ok(())
}

#[derive(Clone, Copy)]
enum UsedAsCA { Yes, No }

fn used_as_ca(ee_or_ca: EndEntityOrCA) -> UsedAsCA {
    match ee_or_ca {
        EndEntityOrCA::EndEntity => UsedAsCA::No,
        EndEntityOrCA::CA(..) => UsedAsCA::Yes
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
fn check_basic_constraints(input: Option<&mut Reader>, used_as_ca: UsedAsCA,
                           sub_ca_count: usize) -> Result<(), Error> {
    let (is_ca, path_len_constraint) = match input {
        Some(input) => {
            let is_ca = try!(der::optional_boolean(input));

            // https://bugzilla.mozilla.org/show_bug.cgi?id=985025: RFC 5280
            // says that a certificate must not have pathLenConstraint unless
            // it is a CA certificate, but some real-world end-entity
            // certificates have pathLenConstraint.
            let path_len_constraint =
                if !input.at_end() {
                    let value = try!(der::integer(input));
                    Some(value as usize)
                } else {
                    None
                };

            (is_ca, path_len_constraint)
        },
        None => (false, None)
    };

    match (used_as_ca, is_ca, path_len_constraint) {
        (UsedAsCA::No, true, _) => Err(Error::CAUsedAsEndEntity),
        (UsedAsCA::Yes, false, _) => Err(Error::EndEntityUsedAsCA),
        (UsedAsCA::Yes, true, Some(len)) if sub_ca_count > len =>
            Err(Error::PathLenConstraintViolated),
        _ => Ok(())
    }
}
