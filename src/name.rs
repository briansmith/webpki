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

use super::input::{Input, Reader};

#[derive(PartialEq)]
enum AllowWildcards {
    No,
    Yes
}

#[derive(PartialEq)]
enum IDRole {
  ReferenceID,
  PresentedID,
  NameConstraint,
}

fn is_valid_reference_dns_id(hostname: Input) -> bool {
    is_valid_dns_id(hostname, IDRole::ReferenceID, AllowWildcards::No)
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.6:
//
//   When the subjectAltName extension contains a domain name system
//   label, the domain name MUST be stored in the dNSName (an IA5String).
//   The name MUST be in the "preferred name syntax", as specified by
//   Section 3.5 of [RFC1034] and as modified by Section 2.1 of
//   [RFC1123].
//
// https://bugzilla.mozilla.org/show_bug.cgi?id=1136616: As an exception to the
// requirement above, underscores are also allowed in names for compatibility.
fn is_valid_dns_id(hostname: Input, id_role: IDRole,
                   allow_wildcards: AllowWildcards) -> bool {
    if hostname.len() > 255 {
        return false;
    }

    let mut input = Reader::new(hostname);

    if id_role == IDRole::NameConstraint && input.at_end() {
        return true;
    }

    let mut dot_count = 0;
    let mut label_length = 0;
    let mut label_is_all_numeric = false;
    let mut label_ends_with_hyphen = false;

    // Only presented IDs are allowed to have wildcard labels. And, like
    // Chromium, be stricter than RFC 6125 requires by insisting that a
    // wildcard label consist only of '*'.
    let is_wildcard = allow_wildcards == AllowWildcards::Yes &&
                     input.peek(b'*');
    let mut is_first_byte = !is_wildcard;
    if is_wildcard {
        if input.read_byte() != Some(b'*') ||
           input.read_byte() != Some(b'.') {
            return false;
        }
        dot_count += 1;
    }

    loop {
        const MAX_LABEL_LENGTH: usize = 63;

        match input.read_byte() {
            Some(b'-') => {
                if label_length == 0 {
                    return false; // Labels must not start with a hyphen.
                }
                label_is_all_numeric = false;
                label_ends_with_hyphen = true;
                label_length += 1;
                if label_length > MAX_LABEL_LENGTH {
                    return false;
                }
            },

            Some(b'0'...b'9') => {
                if label_length == 0 {
                    label_is_all_numeric = true;
                }
                label_ends_with_hyphen = false;
                label_length += 1;
                if label_length > MAX_LABEL_LENGTH {
                    return false;
                }
            },

            Some(b'a'...b'z') | Some(b'A'...b'Z') | Some(b'_') => {
                label_is_all_numeric = false;
                label_ends_with_hyphen = false;
                label_length += 1;
                if label_length > MAX_LABEL_LENGTH {
                    return false;
                }
            },

            Some(b'.') => {
                dot_count += 1;
                if label_length == 0 &&
                   (id_role != IDRole::NameConstraint || !is_first_byte) {
                  return false;
                }
                if label_ends_with_hyphen {
                  return false; // Labels must not end with a hyphen.
                }
                label_length = 0;
            },

            _ => { return false; }
        }
        is_first_byte = false;

        if input.at_end() {
            break;
        }
    }

    // Only reference IDs, not presented IDs or name constraints, may be
    // absolute.
    if label_length == 0 && id_role != IDRole::ReferenceID {
        return false;
    }

    if label_ends_with_hyphen {
        return false; // Labels must not end with a hyphen.
    }

    if label_is_all_numeric {
        return false; // Last label must not be all numeric.
    }

    if is_wildcard {
        // If the DNS ID ends with a dot, the last dot signifies an absolute ID.
        let label_count = if label_length == 0 { dot_count }
                          else { dot_count + 1 };

        // Like NSS, require at least two labels to follow the wildcard label.
        // TODO: Allow the TrustDomain to control this on a per-eTLD+1 basis,
        // similar to Chromium. Even then, it might be better to still enforce
        // that there are at least two labels after the wildcard.
        if label_count < 3 {
            return false;
        }

        // XXX: RFC6125 says that we shouldn't accept wildcards within an IDN
        // A-Label. The consequence of this is that we effectively discriminate
        // against users of languages that cannot be encoded with ASCII.
        let mut maybe_idn = Reader::new(hostname);
        if maybe_idn.read_byte() == Some(b'x') &&
           maybe_idn.read_byte() == Some(b'n') &&
           maybe_idn.read_byte() == Some(b'-') &&
           maybe_idn.read_byte() == Some(b'-') {
            return false;
        }
    }

    true
}
