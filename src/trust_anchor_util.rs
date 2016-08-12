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

use std;
use super::{Error, TrustAnchor};
use super::cert::{EndEntityOrCA, Cert, parse_cert};
use super::cert::certificate_serial_number;
use super::der;
use untrusted;

/// Interprets the given DER-encoded certificate as a `TrustAnchor`. The
/// certificate is not validated. In particular, there is no check that the
/// certificate is self-signed or even that the certificate has the cA basic
/// constraint.
pub fn cert_der_as_trust_anchor<'a>(cert_der: untrusted::Input<'a>)
                                    -> Result<TrustAnchor<'a>, Error> {
    // XXX: `EndEntityOrCA::EndEntity` is used instead of `EndEntityOrCA::CA`
    // because we don't have a reference to a child cert, which is needed for
    // `EndEntityOrCA::CA`. For this purpose, it doesn't matter.
    parse_cert(cert_der, EndEntityOrCA::EndEntity)
        .map(trust_anchor_from_cert)
        .or_else(|err| parse_cert_v1(cert_der)
                 .or(Err(err)))
}

/// Generates code for hard-coding the given trust anchors into a program. This
/// is designed to be used in a build script. `name` is the name of the public
/// static variable that will contain the TrustAnchor array.
pub fn generate_code_for_trust_anchors(name: &str,
                                       trust_anchors: &[TrustAnchor])
                                       -> std::string::String {
    let decl = format!("static {}: [TrustAnchor<'static>; {}] = ", name,
                       trust_anchors.len());

    // "{:?}" formats the array of trust anchors as Rust code, approximately,
    // except that it drops the leading "&" on slices.
    let value = str::replace(&format!("{:?};\n", trust_anchors), ": [", ": &[");

    decl + &value
}

fn trust_anchor_from_cert<'a>(cert: Cert<'a>) -> TrustAnchor<'a> {
    TrustAnchor {
        subject: cert.subject.as_slice_less_safe(),
        spki: cert.spki.as_slice_less_safe(),
        name_constraints: cert.name_constraints
                              .map(|nc| nc.as_slice_less_safe())
    }
}

/// Parses a v1 certificate directly into a TrustAnchor.
fn parse_cert_v1<'a>(cert_der: untrusted::Input<'a>)
                     -> Result<TrustAnchor<'a>, Error> {
    fn skip(input: &mut untrusted::Reader, tag: der::Tag)
            -> Result<(), Error> {
        let _ = try!(der::expect_tag_and_get_input(input, tag));
        Ok(())
    }

    // X.509 Certificate: https://tools.ietf.org/html/rfc5280#section-4.1.
    cert_der.read_all(Error::BadDER, |cert_der| {
        der::nested(cert_der, der::Tag::Sequence, Error::BadDER, |cert_der| {
            let anchor = der::nested(cert_der, der::Tag::Sequence,
                                     Error::BadDER, |tbs| {
                // The version number field does not appear in v1 certificates.
                try!(certificate_serial_number(tbs));

                try!(skip(tbs, der::Tag::Sequence)); // signature.
                try!(skip(tbs, der::Tag::Sequence)); // issuer.
                try!(skip(tbs, der::Tag::Sequence)); // validity.
                let subject =
                    try!(der::expect_tag_and_get_input(tbs,
                                                       der::Tag::Sequence));
                let spki =
                    try!(der::expect_tag_and_get_input(tbs,
                                                       der::Tag::Sequence));

                Ok(TrustAnchor {
                    subject: subject.as_slice_less_safe(),
                    spki: spki.as_slice_less_safe(),
                    name_constraints: None
                })
            });

            // read and discard signatureAlgorithm + signature
            try!(skip(cert_der, der::Tag::Sequence));
            try!(skip(cert_der, der::Tag::BitString));

            anchor
        })
    })
}
