// Copyright 2015-2020 Brian Smith.
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

#[cfg(feature = "alloc")]
use alloc::string::String;

/// A DNS Name suitable for use in the TLS Server Name Indication (SNI)
/// extension and/or for use as the reference hostname for which to verify a
/// certificate.
///
/// A `DnsName` is guaranteed to be syntactically valid. The validity rules are
/// specified in [RFC 5280 Section 7.2], except that underscores are also
/// allowed.
///
/// `DnsName` stores a copy of the input it was constructed from in a `String`
/// and so it is only available when the `std` default feature is enabled.
///
/// `Eq`, `PartialEq`, etc. are not implemented because name comparison
/// frequently should be done case-insensitively and/or with other caveats that
/// depend on the specific circumstances in which the comparison is done.
///
/// [RFC 5280 Section 7.2]: https://tools.ietf.org/html/rfc5280#section-7.2
///
/// Requires the `alloc` feature.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DnsName(String);

/// Requires the `alloc` feature.
#[cfg(feature = "alloc")]
impl DnsName {
    /// Returns a `DnsNameRef` that refers to this `DnsName`.
    pub fn as_ref(&self) -> DnsNameRef {
        DnsNameRef(self.0.as_bytes())
    }
}

/// Requires the `alloc` feature.
#[cfg(feature = "alloc")]
impl AsRef<str> for DnsName {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

/// Requires the `alloc` feature.
// Deprecated
#[cfg(feature = "alloc")]
impl From<DnsNameRef<'_>> for DnsName {
    fn from(dns_name: DnsNameRef) -> Self {
        dns_name.to_owned()
    }
}

/// A reference to a DNS Name suitable for use in the TLS Server Name Indication
/// (SNI) extension and/or for use as the reference hostname for which to verify
/// a certificate.
///
/// A `DnsNameRef` is guaranteed to be syntactically valid. The validity rules
/// are specified in [RFC 5280 Section 7.2], except that underscores are also
/// allowed.
///
/// `Eq`, `PartialEq`, etc. are not implemented because name comparison
/// frequently should be done case-insensitively and/or with other caveats that
/// depend on the specific circumstances in which the comparison is done.
///
/// [RFC 5280 Section 7.2]: https://tools.ietf.org/html/rfc5280#section-7.2
#[derive(Clone, Copy)]
pub struct DnsNameRef<'a>(&'a [u8]);

impl AsRef<[u8]> for DnsNameRef<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

/// An error indicating that a `DnsNameRef` could not built because the input
/// is not a syntactically-valid DNS Name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDnsNameError;

impl core::fmt::Display for InvalidDnsNameError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Requires the `std` feature.
#[cfg(feature = "std")]
impl ::std::error::Error for InvalidDnsNameError {}

impl<'a> DnsNameRef<'a> {
    /// Constructs a `DnsNameRef` from the given input if the input is a
    /// syntactically-valid DNS name.
    pub fn try_from_ascii(dns_name: &'a [u8]) -> Result<Self, InvalidDnsNameError> {
        if !is_valid_reference_dns_id(untrusted::Input::from(dns_name)) {
            return Err(InvalidDnsNameError);
        }

        Ok(Self(dns_name))
    }

    /// Constructs a `DnsNameRef` from the given input if the input is a
    /// syntactically-valid DNS name.
    pub fn try_from_ascii_str(dns_name: &'a str) -> Result<Self, InvalidDnsNameError> {
        Self::try_from_ascii(dns_name.as_bytes())
    }

    /// Constructs a `DnsName` from this `DnsNameRef`
    ///
    /// Requires the `alloc` feature.
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> DnsName {
        // DnsNameRef is already guaranteed to be valid ASCII, which is a
        // subset of UTF-8.
        let s: &str = self.clone().into();
        DnsName(s.to_ascii_lowercase())
    }
}

/// Requires the `alloc` feature.
#[cfg(feature = "alloc")]
impl core::fmt::Debug for DnsNameRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        let lowercase = self.clone().to_owned();
        f.debug_tuple("DnsNameRef").field(&lowercase.0).finish()
    }
}

impl<'a> From<DnsNameRef<'a>> for &'a str {
    fn from(DnsNameRef(d): DnsNameRef<'a>) -> Self {
        // The unwrap won't fail because DnsNameRefs are guaranteed to be ASCII
        // and ASCII is a subset of UTF-8.
        core::str::from_utf8(d).unwrap()
    }
}

pub(super) fn presented_id_matches_reference_id(
    presented_dns_id: untrusted::Input,
    reference_dns_id: untrusted::Input,
) -> Option<bool> {
    presented_id_matches_reference_id_internal(
        presented_dns_id,
        IdRole::Reference,
        reference_dns_id,
    )
}

pub(super) fn presented_id_matches_constraint(
    presented_dns_id: untrusted::Input,
    reference_dns_id: untrusted::Input,
) -> Option<bool> {
    presented_id_matches_reference_id_internal(
        presented_dns_id,
        IdRole::NameConstraint,
        reference_dns_id,
    )
}

// We do not distinguish between a syntactically-invalid presented_dns_id and
// one that is syntactically valid but does not match reference_dns_id; in both
// cases, the result is false.
//
// We assume that both presented_dns_id and reference_dns_id are encoded in
// such a way that US-ASCII (7-bit) characters are encoded in one byte and no
// encoding of a non-US-ASCII character contains a code point in the range
// 0-127. For example, UTF-8 is OK but UTF-16 is not.
//
// RFC6125 says that a wildcard label may be of the form <x>*<y>.<DNSID>, where
// <x> and/or <y> may be empty. However, NSS requires <y> to be empty, and we
// follow NSS's stricter policy by accepting wildcards only of the form
// <x>*.<DNSID>, where <x> may be empty.
//
// An relative presented DNS ID matches both an absolute reference ID and a
// relative reference ID. Absolute presented DNS IDs are not supported:
//
//      Presented ID   Reference ID  Result
//      -------------------------------------
//      example.com    example.com   Match
//      example.com.   example.com   Mismatch
//      example.com    example.com.  Match
//      example.com.   example.com.  Mismatch
//
// There are more subtleties documented inline in the code.
//
// Name constraints ///////////////////////////////////////////////////////////
//
// This is all RFC 5280 has to say about dNSName constraints:
//
//     DNS name restrictions are expressed as host.example.com.  Any DNS
//     name that can be constructed by simply adding zero or more labels to
//     the left-hand side of the name satisfies the name constraint.  For
//     example, www.host.example.com would satisfy the constraint but
//     host1.example.com would not.
//
// This lack of specificity has lead to a lot of uncertainty regarding
// subdomain matching. In particular, the following questions have been
// raised and answered:
//
//     Q: Does a presented identifier equal (case insensitive) to the name
//        constraint match the constraint? For example, does the presented
//        ID "host.example.com" match a "host.example.com" constraint?
//     A: Yes. RFC5280 says "by simply adding zero or more labels" and this
//        is the case of adding zero labels.
//
//     Q: When the name constraint does not start with ".", do subdomain
//        presented identifiers match it? For example, does the presented
//        ID "www.host.example.com" match a "host.example.com" constraint?
//     A: Yes. RFC5280 says "by simply adding zero or more labels" and this
//        is the case of adding more than zero labels. The example is the
//        one from RFC 5280.
//
//     Q: When the name constraint does not start with ".", does a
//        non-subdomain prefix match it? For example, does "bigfoo.bar.com"
//        match "foo.bar.com"? [4]
//     A: No. We interpret RFC 5280's language of "adding zero or more labels"
//        to mean that whole labels must be prefixed.
//
//     (Note that the above three scenarios are the same as the RFC 6265
//     domain matching rules [0].)
//
//     Q: Is a name constraint that starts with "." valid, and if so, what
//        semantics does it have? For example, does a presented ID of
//        "www.example.com" match a constraint of ".example.com"? Does a
//        presented ID of "example.com" match a constraint of ".example.com"?
//     A: This implementation, NSS[1], and SChannel[2] all support a
//        leading ".", but OpenSSL[3] does not yet. Amongst the
//        implementations that support it, a leading "." is legal and means
//        the same thing as when the "." is omitted, EXCEPT that a
//        presented identifier equal (case insensitive) to the name
//        constraint is not matched; i.e. presented dNSName identifiers
//        must be subdomains. Some CAs in Mozilla's CA program (e.g. HARICA)
//        have name constraints with the leading "." in their root
//        certificates. The name constraints imposed on DCISS by Mozilla also
//        have the it, so supporting this is a requirement for backward
//        compatibility, even if it is not yet standardized. So, for example, a
//        presented ID of "www.example.com" matches a constraint of
//        ".example.com" but a presented ID of "example.com" does not.
//
//     Q: Is there a way to prevent subdomain matches?
//     A: Yes.
//
//        Some people have proposed that dNSName constraints that do not
//        start with a "." should be restricted to exact (case insensitive)
//        matches. However, such a change of semantics from what RFC5280
//        specifies would be a non-backward-compatible change in the case of
//        permittedSubtrees constraints, and it would be a security issue for
//        excludedSubtrees constraints.
//
//        However, it can be done with a combination of permittedSubtrees and
//        excludedSubtrees, e.g. "example.com" in permittedSubtrees and
//        ".example.com" in excludedSubtrees.
//
//     Q: Are name constraints allowed to be specified as absolute names?
//        For example, does a presented ID of "example.com" match a name
//        constraint of "example.com." and vice versa.
//     A: Absolute names are not supported as presented IDs or name
//        constraints. Only reference IDs may be absolute.
//
//     Q: Is "" a valid dNSName constraint? If so, what does it mean?
//     A: Yes. Any valid presented dNSName can be formed "by simply adding zero
//        or more labels to the left-hand side" of "". In particular, an
//        excludedSubtrees dNSName constraint of "" forbids all dNSNames.
//
//     Q: Is "." a valid dNSName constraint? If so, what does it mean?
//     A: No, because absolute names are not allowed (see above).
//
// [0] RFC 6265 (Cookies) Domain Matching rules:
//     http://tools.ietf.org/html/rfc6265#section-5.1.3
// [1] NSS source code:
//     https://mxr.mozilla.org/nss/source/lib/certdb/genname.c?rev=2a7348f013cb#1209
// [2] Description of SChannel's behavior from Microsoft:
//     http://www.imc.org/ietf-pkix/mail-archive/msg04668.html
// [3] Proposal to add such support to OpenSSL:
//     http://www.mail-archive.com/openssl-dev%40openssl.org/msg36204.html
//     https://rt.openssl.org/Ticket/Display.html?id=3562
// [4] Feedback on the lack of clarify in the definition that never got
//     incorporated into the spec:
//     https://www.ietf.org/mail-archive/web/pkix/current/msg21192.html
fn presented_id_matches_reference_id_internal(
    presented_dns_id: untrusted::Input,
    reference_dns_id_role: IdRole,
    reference_dns_id: untrusted::Input,
) -> Option<bool> {
    if !is_valid_dns_id(presented_dns_id, IdRole::Presented, AllowWildcards::Yes) {
        return None;
    }

    if !is_valid_dns_id(reference_dns_id, reference_dns_id_role, AllowWildcards::No) {
        return None;
    }

    let mut presented = untrusted::Reader::new(presented_dns_id);
    let mut reference = untrusted::Reader::new(reference_dns_id);

    match reference_dns_id_role {
        IdRole::Reference => (),

        IdRole::NameConstraint if presented_dns_id.len() > reference_dns_id.len() => {
            if reference_dns_id.is_empty() {
                // An empty constraint matches everything.
                return Some(true);
            }

            // If the reference ID starts with a dot then skip the prefix of
            // the presented ID and start the comparison at the position of
            // that dot. Examples:
            //
            //                                       Matches     Doesn't Match
            //     -----------------------------------------------------------
            //       original presented ID:  www.example.com    badexample.com
            //                     skipped:  www                ba
            //     presented ID w/o prefix:     .example.com      dexample.com
            //                reference ID:     .example.com      .example.com
            //
            // If the reference ID does not start with a dot then we skip
            // the prefix of the presented ID but also verify that the
            // prefix ends with a dot. Examples:
            //
            //                                       Matches     Doesn't Match
            //     -----------------------------------------------------------
            //       original presented ID:  www.example.com    badexample.com
            //                     skipped:  www                ba
            //                 must be '.':     .                 d
            //     presented ID w/o prefix:      example.com       example.com
            //                reference ID:      example.com       example.com
            //
            if reference.peek(b'.') {
                if presented
                    .skip(presented_dns_id.len() - reference_dns_id.len())
                    .is_err()
                {
                    unreachable!();
                }
            } else {
                if presented
                    .skip(presented_dns_id.len() - reference_dns_id.len() - 1)
                    .is_err()
                {
                    unreachable!();
                }
                if presented.read_byte() != Ok(b'.') {
                    return Some(false);
                }
            }
        }

        IdRole::NameConstraint => (),

        IdRole::Presented => unreachable!(),
    }

    // Only allow wildcard labels that consist only of '*'.
    if presented.peek(b'*') {
        if presented.skip(1).is_err() {
            unreachable!();
        }

        loop {
            if reference.read_byte().is_err() {
                return Some(false);
            }
            if reference.peek(b'.') {
                break;
            }
        }
    }

    loop {
        let presented_byte = match (presented.read_byte(), reference.read_byte()) {
            (Ok(p), Ok(r)) if ascii_lower(p) == ascii_lower(r) => p,
            _ => {
                return Some(false);
            }
        };

        if presented.at_end() {
            // Don't allow presented IDs to be absolute.
            if presented_byte == b'.' {
                return None;
            }
            break;
        }
    }

    // Allow a relative presented DNS ID to match an absolute reference DNS ID,
    // unless we're matching a name constraint.
    if !reference.at_end() {
        if reference_dns_id_role != IdRole::NameConstraint {
            match reference.read_byte() {
                Ok(b'.') => (),
                _ => {
                    return Some(false);
                }
            };
        }
        if !reference.at_end() {
            return Some(false);
        }
    }

    assert!(presented.at_end());
    assert!(reference.at_end());

    Some(true)
}

#[inline]
fn ascii_lower(b: u8) -> u8 {
    match b {
        b'A'..=b'Z' => b + b'a' - b'A',
        _ => b,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum AllowWildcards {
    No,
    Yes,
}

#[derive(Clone, Copy, PartialEq)]
enum IdRole {
    Reference,
    Presented,
    NameConstraint,
}

fn is_valid_reference_dns_id(hostname: untrusted::Input) -> bool {
    is_valid_dns_id(hostname, IdRole::Reference, AllowWildcards::No)
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
fn is_valid_dns_id(
    hostname: untrusted::Input,
    id_role: IdRole,
    allow_wildcards: AllowWildcards,
) -> bool {
    // https://blogs.msdn.microsoft.com/oldnewthing/20120412-00/?p=7873/
    if hostname.len() > 253 {
        return false;
    }

    let mut input = untrusted::Reader::new(hostname);

    if id_role == IdRole::NameConstraint && input.at_end() {
        return true;
    }

    let mut dot_count = 0;
    let mut label_length = 0;
    let mut label_is_all_numeric = false;
    let mut label_ends_with_hyphen = false;

    // Only presented IDs are allowed to have wildcard labels. And, like
    // Chromium, be stricter than RFC 6125 requires by insisting that a
    // wildcard label consist only of '*'.
    let is_wildcard = allow_wildcards == AllowWildcards::Yes && input.peek(b'*');
    let mut is_first_byte = !is_wildcard;
    if is_wildcard {
        if input.read_byte() != Ok(b'*') || input.read_byte() != Ok(b'.') {
            return false;
        }
        dot_count += 1;
    }

    loop {
        const MAX_LABEL_LENGTH: usize = 63;

        match input.read_byte() {
            Ok(b'-') => {
                if label_length == 0 {
                    return false; // Labels must not start with a hyphen.
                }
                label_is_all_numeric = false;
                label_ends_with_hyphen = true;
                label_length += 1;
                if label_length > MAX_LABEL_LENGTH {
                    return false;
                }
            }

            Ok(b'0'..=b'9') => {
                if label_length == 0 {
                    label_is_all_numeric = true;
                }
                label_ends_with_hyphen = false;
                label_length += 1;
                if label_length > MAX_LABEL_LENGTH {
                    return false;
                }
            }

            Ok(b'a'..=b'z') | Ok(b'A'..=b'Z') | Ok(b'_') => {
                label_is_all_numeric = false;
                label_ends_with_hyphen = false;
                label_length += 1;
                if label_length > MAX_LABEL_LENGTH {
                    return false;
                }
            }

            Ok(b'.') => {
                dot_count += 1;
                if label_length == 0 && (id_role != IdRole::NameConstraint || !is_first_byte) {
                    return false;
                }
                if label_ends_with_hyphen {
                    return false; // Labels must not end with a hyphen.
                }
                label_length = 0;
            }

            _ => {
                return false;
            }
        }
        is_first_byte = false;

        if input.at_end() {
            break;
        }
    }

    // Only reference IDs, not presented IDs or name constraints, may be
    // absolute.
    if label_length == 0 && id_role != IdRole::Reference {
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
        let label_count = if label_length == 0 {
            dot_count
        } else {
            dot_count + 1
        };

        // Like NSS, require at least two labels to follow the wildcard label.
        // TODO: Allow the TrustDomain to control this on a per-eTLD+1 basis,
        // similar to Chromium. Even then, it might be better to still enforce
        // that there are at least two labels after the wildcard.
        if label_count < 3 {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRESENTED_MATCHES_REFERENCE: &[(&[u8], &[u8], Option<bool>)] = &[
        (b"", b"a", None),
        (b"a", b"a", Some(true)),
        (b"b", b"a", Some(false)),
        (b"*.b.a", b"c.b.a", Some(true)),
        (b"*.b.a", b"b.a", Some(false)),
        (b"*.b.a", b"b.a.", Some(false)),
        // Wildcard not in leftmost label
        (b"d.c.b.a", b"d.c.b.a", Some(true)),
        (b"d.*.b.a", b"d.c.b.a", None),
        (b"d.c*.b.a", b"d.c.b.a", None),
        (b"d.c*.b.a", b"d.cc.b.a", None),
        // case sensitivity
        (
            b"abcdefghijklmnopqrstuvwxyz",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            Some(true),
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            b"abcdefghijklmnopqrstuvwxyz",
            Some(true),
        ),
        (b"aBc", b"Abc", Some(true)),
        // digits
        (b"a1", b"a1", Some(true)),
        // A trailing dot indicates an absolute name, and absolute names can match
        // relative names, and vice-versa.
        (b"example", b"example", Some(true)),
        (b"example.", b"example.", None),
        (b"example", b"example.", Some(true)),
        (b"example.", b"example", None),
        (b"example.com", b"example.com", Some(true)),
        (b"example.com.", b"example.com.", None),
        (b"example.com", b"example.com.", Some(true)),
        (b"example.com.", b"example.com", None),
        (b"example.com..", b"example.com.", None),
        (b"example.com..", b"example.com", None),
        (b"example.com...", b"example.com.", None),
        // xn-- IDN prefix
        (b"x*.b.a", b"xa.b.a", None),
        (b"x*.b.a", b"xna.b.a", None),
        (b"x*.b.a", b"xn-a.b.a", None),
        (b"x*.b.a", b"xn--a.b.a", None),
        (b"xn*.b.a", b"xn--a.b.a", None),
        (b"xn-*.b.a", b"xn--a.b.a", None),
        (b"xn--*.b.a", b"xn--a.b.a", None),
        (b"xn*.b.a", b"xn--a.b.a", None),
        (b"xn-*.b.a", b"xn--a.b.a", None),
        (b"xn--*.b.a", b"xn--a.b.a", None),
        (b"xn---*.b.a", b"xn--a.b.a", None),
        // "*" cannot expand to nothing.
        (b"c*.b.a", b"c.b.a", None),
        // --------------------------------------------------------------------------
        // The rest of these are test cases adapted from Chromium's
        // x509_certificate_unittest.cc. The parameter order is the opposite in
        // Chromium's tests. Also, they some tests were modified to fit into this
        // framework or due to intentional differences between mozilla::pkix and
        // Chromium.
        (b"foo.com", b"foo.com", Some(true)),
        (b"f", b"f", Some(true)),
        (b"i", b"h", Some(false)),
        (b"*.foo.com", b"bar.foo.com", Some(true)),
        (b"*.test.fr", b"www.test.fr", Some(true)),
        (b"*.test.FR", b"wwW.tESt.fr", Some(true)),
        (b".uk", b"f.uk", None),
        (b"?.bar.foo.com", b"w.bar.foo.com", None),
        (b"(www|ftp).foo.com", b"www.foo.com", None), // regex!
        (b"www.foo.com\0", b"www.foo.com", None),
        (b"www.foo.com\0*.foo.com", b"www.foo.com", None),
        (b"ww.house.example", b"www.house.example", Some(false)),
        (b"www.test.org", b"test.org", Some(false)),
        (b"*.test.org", b"test.org", Some(false)),
        (b"*.org", b"test.org", None),
        // '*' must be the only character in the wildcard label
        (b"w*.bar.foo.com", b"w.bar.foo.com", None),
        (b"ww*ww.bar.foo.com", b"www.bar.foo.com", None),
        (b"ww*ww.bar.foo.com", b"wwww.bar.foo.com", None),
        (b"w*w.bar.foo.com", b"wwww.bar.foo.com", None),
        (b"w*w.bar.foo.c0m", b"wwww.bar.foo.com", None),
        (b"wa*.bar.foo.com", b"WALLY.bar.foo.com", None),
        (b"*Ly.bar.foo.com", b"wally.bar.foo.com", None),
        // Chromium does URL decoding of the reference ID, but we don't, and we also
        // require that the reference ID is valid, so we can't test these two.
        //     (b"www.foo.com", b"ww%57.foo.com", Some(true)),
        //     (b"www&.foo.com", b"www%26.foo.com", Some(true)),
        (b"*.test.de", b"www.test.co.jp", Some(false)),
        (b"*.jp", b"www.test.co.jp", None),
        (b"www.test.co.uk", b"www.test.co.jp", Some(false)),
        (b"www.*.co.jp", b"www.test.co.jp", None),
        (b"www.bar.foo.com", b"www.bar.foo.com", Some(true)),
        (b"*.foo.com", b"www.bar.foo.com", Some(false)),
        (b"*.*.foo.com", b"www.bar.foo.com", None),
        // Our matcher requires the reference ID to be a valid DNS name, so we cannot
        // test this case.
        //     (b"*.*.bar.foo.com", b"*..bar.foo.com", Some(false)),
        (b"www.bath.org", b"www.bath.org", Some(true)),
        // Our matcher requires the reference ID to be a valid DNS name, so we cannot
        // test these cases.
        // DNS_ID_MISMATCH("www.bath.org", ""),
        //     (b"www.bath.org", b"20.30.40.50", Some(false)),
        //     (b"www.bath.org", b"66.77.88.99", Some(false)),

        // IDN tests
        (
            b"xn--poema-9qae5a.com.br",
            b"xn--poema-9qae5a.com.br",
            Some(true),
        ),
        (
            b"*.xn--poema-9qae5a.com.br",
            b"www.xn--poema-9qae5a.com.br",
            Some(true),
        ),
        (
            b"*.xn--poema-9qae5a.com.br",
            b"xn--poema-9qae5a.com.br",
            Some(false),
        ),
        (b"xn--poema-*.com.br", b"xn--poema-9qae5a.com.br", None),
        (b"xn--*-9qae5a.com.br", b"xn--poema-9qae5a.com.br", None),
        (b"*--poema-9qae5a.com.br", b"xn--poema-9qae5a.com.br", None),
        // The following are adapted from the examples quoted from
        //   http://tools.ietf.org/html/rfc6125#section-6.4.3
        // (e.g., *.example.com would match foo.example.com but
        // not bar.foo.example.com or example.com).
        (b"*.example.com", b"foo.example.com", Some(true)),
        (b"*.example.com", b"bar.foo.example.com", Some(false)),
        (b"*.example.com", b"example.com", Some(false)),
        (b"baz*.example.net", b"baz1.example.net", None),
        (b"*baz.example.net", b"foobaz.example.net", None),
        (b"b*z.example.net", b"buzz.example.net", None),
        // Wildcards should not be valid for public registry controlled domains,
        // and unknown/unrecognized domains, at least three domain components must
        // be present. For mozilla::pkix and NSS, there must always be at least two
        // labels after the wildcard label.
        (b"*.test.example", b"www.test.example", Some(true)),
        (b"*.example.co.uk", b"test.example.co.uk", Some(true)),
        (b"*.example", b"test.example", None),
        // The result is different than Chromium, because Chromium takes into account
        // the additional knowledge it has that "co.uk" is a TLD. mozilla::pkix does
        // not know that.
        (b"*.co.uk", b"example.co.uk", Some(true)),
        (b"*.com", b"foo.com", None),
        (b"*.us", b"foo.us", None),
        (b"*", b"foo", None),
        // IDN variants of wildcards and registry controlled domains.
        (
            b"*.xn--poema-9qae5a.com.br",
            b"www.xn--poema-9qae5a.com.br",
            Some(true),
        ),
        (
            b"*.example.xn--mgbaam7a8h",
            b"test.example.xn--mgbaam7a8h",
            Some(true),
        ),
        // RFC6126 allows this, and NSS accepts it, but Chromium disallows it.
        // TODO: File bug against Chromium.
        (b"*.com.br", b"xn--poema-9qae5a.com.br", Some(true)),
        (b"*.xn--mgbaam7a8h", b"example.xn--mgbaam7a8h", None),
        // Wildcards should be permissible for 'private' registry-controlled
        // domains. (In mozilla::pkix, we do not know if it is a private registry-
        // controlled domain or not.)
        (b"*.appspot.com", b"www.appspot.com", Some(true)),
        (b"*.s3.amazonaws.com", b"foo.s3.amazonaws.com", Some(true)),
        // Multiple wildcards are not valid.
        (b"*.*.com", b"foo.example.com", None),
        (b"*.bar.*.com", b"foo.bar.example.com", None),
        // Absolute vs relative DNS name tests. Although not explicitly specified
        // in RFC 6125, absolute reference names (those ending in a .) should
        // match either absolute or relative presented names.
        // TODO: File errata against RFC 6125 about this.
        (b"foo.com.", b"foo.com", None),
        (b"foo.com", b"foo.com.", Some(true)),
        (b"foo.com.", b"foo.com.", None),
        (b"f.", b"f", None),
        (b"f", b"f.", Some(true)),
        (b"f.", b"f.", None),
        (b"*.bar.foo.com.", b"www-3.bar.foo.com", None),
        (b"*.bar.foo.com", b"www-3.bar.foo.com.", Some(true)),
        (b"*.bar.foo.com.", b"www-3.bar.foo.com.", None),
        // We require the reference ID to be a valid DNS name, so we cannot test this
        // case.
        //     (b".", b".", Some(false)),
        (b"*.com.", b"example.com", None),
        (b"*.com", b"example.com.", None),
        (b"*.com.", b"example.com.", None),
        (b"*.", b"foo.", None),
        (b"*.", b"foo", None),
        // The result is different than Chromium because we don't know that co.uk is
        // a TLD.
        (b"*.co.uk.", b"foo.co.uk", None),
        (b"*.co.uk.", b"foo.co.uk.", None),
    ];

    #[test]
    fn presented_matches_reference_test() {
        for &(presented, reference, expected_result) in PRESENTED_MATCHES_REFERENCE {
            let actual_result = presented_id_matches_reference_id(
                untrusted::Input::from(presented),
                untrusted::Input::from(reference),
            );
            assert_eq!(
                actual_result,
                expected_result,
                "presented_dns_id_matches_reference_dns_id(\"{:?}\", IDRole::ReferenceID, \"{:?}\")",
                presented,
                reference
            );
        }
    }
}
