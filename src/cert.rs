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
use super::der;
use super::input::*;
use super::signed_data::{parse_signed_data, SignedData};

pub enum EndEntityOrCA<'a> {
    EndEntity,
    CA(&'a Cert<'a>),
}

pub struct Cert<'a> {
    pub ee_or_ca: EndEntityOrCA<'a>,

    signed_data: SignedData<'a>,
    pub issuer: Input<'a>,
    pub validity: Input<'a>,
    pub subject: Input<'a>,
    pub spki: Input<'a>,

    authority_info_access: Option<Input<'a>>,
    pub basic_constraints: Option<Input<'a>>,
    pub eku: Option<Input<'a>>,
    pub name_constraints: Option<Input<'a>>,
    subject_alt_name: Option<Input<'a>>,
}

pub fn parse_cert<'a>(cert_der: Input<'a>, ee_or_ca: EndEntityOrCA<'a>)
                      -> Result<Cert<'a>, Error> {
    let (tbs, signed_data) = try!(read_all(cert_der, Error::BadDER, |cert_der| {
        der::nested(cert_der, der::Tag::Sequence, parse_signed_data)
    }));

    read_all(tbs, Error::BadDER, |tbs| {
        try!(version3(tbs));
        let _serial_number = try!(certificate_serial_number(tbs));

        let signature =
            try!(der::expect_tag_and_get_input(tbs, der::Tag::Sequence));
        // TODO: In mozilla::pkix, the comparison is done based on the
        // normalized value (ignoring whether or not there is an optional NULL
        // parameter for RSA-based algorithms), so this may be too strict.
        if signature != signed_data.algorithm {
            return Err(Error::SignatureAlgorithmMismatch);
        }

        let issuer =
            try!(der::expect_tag_and_get_input(tbs, der::Tag::Sequence));
        let validity =
            try!(der::expect_tag_and_get_input(tbs, der::Tag::Sequence));
        let subject =
            try!(der::expect_tag_and_get_input(tbs, der::Tag::Sequence));
        let spki =
            try!(der::expect_tag_and_get_input(tbs, der::Tag::Sequence));

        // In theory there could be fields [1] issuerUniqueID and [2]
        // subjectUniqueID, but in practice there never are, and to keep the
        // code small and simple we don't accept any certificates that do
        // contain them.

        let mut cert: Cert<'a> = Cert {
            ee_or_ca: ee_or_ca,

            signed_data: signed_data,
            issuer: issuer,
            validity: validity,
            subject: subject,
            spki: spki,

            authority_info_access: None,
            basic_constraints: None,
            eku: None,
            name_constraints: None,
            subject_alt_name: None,
        };

        // mozilla::pkix allows the extensions to be omitted. However, since
        // the subjectAltName extension is mandatory, the extensions are
        // mandatory too, and we enforce that. Also, mozilla::pkix includes
        // special logic for handling critical Netscape Cert Type extensions.
        // That has been intentionally omitted.

        try!(der::nested_mut(tbs, der::Tag::ContextSpecificConstructed3,
                             |tagged| {
            der::nested_of_mut(tagged, der::Tag::Sequence, der::Tag::Sequence,
                               |extension| {
                let extn_id = try!(der::expect_tag_and_get_input(extension,
                                                                 der::Tag::OID));
                let critical = try!(der::optional_boolean(extension));
                let extn_value: Input<'a> =
                    try!(der::expect_tag_and_get_input(extension,
                                                       der::Tag::OctetString));
                match try!(remember_extension(&mut cert, extn_id, extn_value)) {
                    Understood::No if critical => {
                        Err(Error::UnsupportedCriticalExtension)
                    },
                    _ => Ok(())
                }
            })
        }));

        Ok(cert)
    })
}

// mozilla::pkix supports v1, v2, v3, and v4, including both the implicit
// (correct) and explicit (incorrect) encoding of v1. We allow only v3.
fn version3(input: &mut Reader) -> Result<(), Error> {
    der::nested(input, der::Tag::ContextSpecificConstructed0, |input| {
        let version = try!(der::integer(input));
        if version != 2 { // v3
            return Err(Error::UnsupportedCertVersion);
        }
        Ok(())
    })
}

fn certificate_serial_number<'a>(input: &mut Reader<'a>)
                                 -> Result<Input<'a>, Error> {
    // https://tools.ietf.org/html/rfc5280#section-4.1.2.2:
    // * Conforming CAs MUST NOT use serialNumber values longer than 20 octets."
    // * "The serial number MUST be a positive integer [...]"

    let value = try!(der::expect_tag_and_get_input(input, der::Tag::Integer));
    if value.len() > 20 {
        return Err(Error::BadDER);
    }

    // TODO: Enforce that the integer value is encoded properly and that it is
    // a positive integer.
    Ok(value)
}

enum Understood { Yes, No }

fn remember_extension<'a>(cert: &mut Cert<'a>, extn_id: Input, value: Input<'a>)
                          -> Result<Understood, Error> {
    // python DottedOIDToCode.py id-ce-basicConstraints 2.5.29.19
    const ID_CE_BASICCONSTRAINTS: [u8; 3] = [
        0x55, 0x1d, 0x13
    ];

    // python DottedOIDToCode.py id-ce-extKeyUsage 2.5.29.37
    const ID_CE_EXTKEYUSAGE: [u8; 3] = [
        0x55, 0x1d, 0x25
    ];

    // python DottedOIDToCode.py id-ce-keyUsage 2.5.29.15
    const ID_CE_KEYUSAGE: [u8; 3] = [
        0x55, 0x1d, 0x0f
    ];

    // python DottedOIDToCode.py id-ce-nameConstraints 2.5.29.30
    const ID_CE_NAMECONSTRAINTS: [u8; 3] = [
        0x55, 0x1d, 0x1e
    ];

    // python DottedOIDToCode.py id-ce-subjectAltName 2.5.29.17
    const ID_CE_SUBJECTALTNAME: [u8; 3] = [
        0x55, 0x1d, 0x11
    ];

    // python DottedOIDToCode.py id-pe-authorityInfoAccess 1.3.6.1.5.5.7.1.1
    const ID_PE_AUTHORITYINFOACCESS: [u8; 8] = [
        0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01
    ];

    // We don't do anything with certificate policies so we can safely ignore
    // all policy-related stuff. We assume that the policy-related extensions
    // are not marked critical.

    // TODO: Replace this with pattern matching that deals with common
    // subexpressions.
    let out =
        if input_equals(extn_id, &ID_CE_KEYUSAGE) {
            // We ignore the KeyUsag eextension. For CA certificates,
            // BasicConstraints.cA makes KeyUsage redundant. Firefox and other
            // common browsers do not check KeyUsage for end-entities, though
            // it would be kind of nice to ensure that a KeyUsage without the
            // keyEncipherment bit could not be used for RSA key exchange.
            return Ok(Understood::Yes);
        } else if input_equals(extn_id, &ID_CE_BASICCONSTRAINTS) {
            &mut cert.basic_constraints
        } else if input_equals(extn_id, &ID_CE_EXTKEYUSAGE) {
            &mut cert.eku
        } else if input_equals(extn_id, &ID_CE_NAMECONSTRAINTS) {
            &mut cert.name_constraints
        } else if input_equals(extn_id, &ID_CE_SUBJECTALTNAME) {
            &mut cert.subject_alt_name
        } else if input_equals(extn_id, &ID_PE_AUTHORITYINFOACCESS) {
            &mut cert.authority_info_access
        } else {
            return Ok(Understood::No);
        };

    match *out {
        Some(..) => {
            // The certificate contains more than one instance of this
            // extension.
            return Err(Error::ExtensionValueInvalid);
        }
        None => {
            // All the extensions that we care about are wrapped in a SEQUENCE.
            let sequence_value = try!(read_all(value, Error::BadDER, |value| {
                der::expect_tag_and_get_input(value, der::Tag::Sequence)
            }));
            *out = Some(sequence_value);
        }
    }

    Ok(Understood::Yes)
}
