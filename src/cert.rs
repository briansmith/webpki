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

use crate::{der, signed_data, Error};
#[cfg(feature = "std")]
use std::collections::HashMap;

pub enum EndEntityOrCa<'a> {
    EndEntity,
    Ca(&'a Cert<'a>),
}

pub struct Cert<'a> {
    pub ee_or_ca: EndEntityOrCa<'a>,

    pub signed_data: signed_data::SignedData<'a>,
    pub issuer: untrusted::Input<'a>,
    pub validity: untrusted::Input<'a>,
    pub subject: untrusted::Input<'a>,
    pub spki: der::Value<'a>,

    pub basic_constraints: Option<untrusted::Input<'a>>,
    pub eku: Option<untrusted::Input<'a>>,
    pub name_constraints: Option<untrusted::Input<'a>>,
    pub subject_alt_name: Option<untrusted::Input<'a>>,
    #[cfg(feature = "std")]
    pub unrecognized_extensions: HashMap<&'a[u8], untrusted::Input<'a>>,
}

pub fn parse_cert<'a>(
    cert_der: untrusted::Input<'a>,
    ee_or_ca: EndEntityOrCa<'a>,
) -> Result<Cert<'a>, Error> {
    parse_cert_internal(cert_der, ee_or_ca, certificate_serial_number)
}

/// Used by `parse_cert` for regular certificates (end-entity and intermediate)
/// and by `cert_der_as_trust_anchor` for trust anchors encoded as
/// certificates.
pub(crate) fn parse_cert_internal<'a>(
    cert_der: untrusted::Input<'a>,
    ee_or_ca: EndEntityOrCa<'a>,
    serial_number: fn(input: &mut untrusted::Reader<'_>) -> Result<(), Error>,
) -> Result<Cert<'a>, Error> {
    let (tbs, signed_data) = cert_der.read_all(Error::BadDER, |cert_der| {
        der::nested(
            cert_der,
            der::Tag::Sequence,
            Error::BadDER,
            signed_data::parse_signed_data,
        )
    })?;

    tbs.read_all(Error::BadDER, |tbs| {
        version3(tbs)?;
        serial_number(tbs)?;

        let signature = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;
        // TODO: In mozilla::pkix, the comparison is done based on the
        // normalized value (ignoring whether or not there is an optional NULL
        // parameter for RSA-based algorithms), so this may be too strict.
        if signature != signed_data.algorithm {
            return Err(Error::SignatureAlgorithmMismatch);
        }

        let issuer = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;
        let validity = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;
        let subject = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;
        let spki = der::expect_tag(tbs, der::Tag::Sequence)?;

        // In theory there could be fields [1] issuerUniqueID and [2]
        // subjectUniqueID, but in practice there never are, and to keep the
        // code small and simple we don't accept any certificates that do
        // contain them.

        let mut cert = Cert {
            ee_or_ca,

            signed_data,
            issuer,
            validity,
            subject,
            spki,

            basic_constraints: None,
            eku: None,
            name_constraints: None,
            subject_alt_name: None,
            #[cfg(feature = "std")]
            unrecognized_extensions: HashMap::new(),
        };

        // mozilla::pkix allows the extensions to be omitted. However, since
        // the subjectAltName extension is mandatory, the extensions are
        // mandatory too, and we enforce that. Also, mozilla::pkix includes
        // special logic for handling critical Netscape Cert Type extensions.
        // That has been intentionally omitted.

        der::nested(
            tbs,
            der::Tag::ContextSpecificConstructed3,
            Error::MissingOrMalformedExtensions,
            |tagged| {
                der::nested_of_mut(
                    tagged,
                    der::Tag::Sequence,
                    der::Tag::Sequence,
                    Error::BadDER,
                    |extension| {
                        let extn_id = der::expect_tag_and_get_value(extension, der::Tag::OID)?;
                        let critical = der::optional_boolean(extension)?;
                        let extn_value =
                            der::expect_tag_and_get_value(extension, der::Tag::OctetString)?;
                        match remember_extension(&mut cert, extn_id, extn_value)? {
                            Understood::No if critical => Err(Error::UnsupportedCriticalExtension),
                            _ => Ok(()),
                        }
                    },
                )
            },
        )?;

        Ok(cert)
    })
}

// mozilla::pkix supports v1, v2, v3, and v4, including both the implicit
// (correct) and explicit (incorrect) encoding of v1. We allow only v3.
fn version3(input: &mut untrusted::Reader) -> Result<(), Error> {
    der::nested(
        input,
        der::Tag::ContextSpecificConstructed0,
        Error::UnsupportedCertVersion,
        |input| {
            let version = der::small_nonnegative_integer(input)?;
            if version != 2 {
                // v3
                return Err(Error::UnsupportedCertVersion);
            }
            Ok(())
        },
    )
}

pub fn certificate_serial_number(input: &mut untrusted::Reader) -> Result<(), Error> {
    // https://tools.ietf.org/html/rfc5280#section-4.1.2.2:
    // * Conforming CAs MUST NOT use serialNumber values longer than 20 octets."
    // * "The serial number MUST be a positive integer [...]"

    let value = der::positive_integer(input)?;
    if value.big_endian_without_leading_zero().len() > 20 {
        return Err(Error::BadDER);
    }
    Ok(())
}

enum Understood {
    Yes,
    No,
}

fn remember_extension<'a>(
    cert: &mut Cert<'a>,
    extn_id: untrusted::Input<'a>,
    value: untrusted::Input<'a>,
) -> Result<Understood, Error> {
    // We don't do anything with certificate policies so we can safely ignore
    // all policy-related stuff. We assume that the policy-related extensions
    // are not marked critical.
    const ID_CE_KEY_USAGE: &[u8] = &oid![2, 5, 29, 15];
    const ID_CE_SUBJECT_ALT_NAME: &[u8] = &oid![2, 5, 29, 17];
    const ID_CE_BASIC_CONSTRAINTS: &[u8] = &oid![2, 5, 29, 19];
    const ID_CE_NAME_CONSTRAINTS: &[u8] = &oid![2, 5, 29, 30];
    const ID_CE_EXT_KEY_USAGE: &[u8] = &oid![2, 5, 29, 37];

    let extension_id = &*extn_id.as_slice_less_safe();
    // note: the "strange" arrays below could be generated by the `oid!` macro. However,
    // I can't find a way to make Rust let me put the output of that macro in a match expression.
    // It looks like it's in progress, however (https://github.com/rust-lang/rust/issues/74446).
    // Until then, I'm afraid we're left with this jankiness (suggestions appreciated)
    let out = match extension_id {
        // id-ce-keyUsage 2.5.29.15. We ignore the KeyUsage extension. For CA
        // certificates, BasicConstraints.cA makes KeyUsage redundant. Firefox
        // and other common browsers do not check KeyUsage for end-entities,
        // though it would be kind of nice to ensure that a KeyUsage without
        // the keyEncipherment bit could not be used for RSA key exchange.
        ID_CE_KEY_USAGE => {
            return Ok(Understood::Yes);
        }

        // id-ce-subjectAltName 2.5.29.17
        ID_CE_SUBJECT_ALT_NAME => &mut cert.subject_alt_name,

        // id-ce-basicConstraints 2.5.29.19
        ID_CE_BASIC_CONSTRAINTS => &mut cert.basic_constraints,

        // id-ce-nameConstraints 2.5.29.30
        ID_CE_NAME_CONSTRAINTS => &mut cert.name_constraints,

        // id-ce-extKeyUsage 2.5.29.37
        ID_CE_EXT_KEY_USAGE => &mut cert.eku,

        //This is not a recognized extension, add it to the unrecognized
        // extension hash and return `Understood::No`
        #[cfg(feature = "std")]
        _ => { 
            let value = value.read_all(Error::BadDER, |value| {
                Ok(value.read_bytes_to_end())
            })?;
            match cert.unrecognized_extensions.insert(extension_id, value) {
                Some(_) => {
                    // There appears to be two unrecognized extensions with the same ID.
                    return Err(Error::ExtensionValueInvalid);
                }
                None => {
                    // Insertion was successful, and the extension is unique to the certificate
                    return Ok(Understood::No)
                },
            }
        }
        #[cfg(not(feature = "std"))]
        _ => {
            return Ok(Understood::No);
        }
    };

    match *out {
        Some(..) => {
            // The certificate contains more than one instance of this
            // extension.
            return Err(Error::ExtensionValueInvalid);
        }
        None => {
            // All the extensions that we care about are wrapped in a SEQUENCE.
            let sequence_value = value.read_all(Error::BadDER, |value| {
                der::expect_tag_and_get_value(value, der::Tag::Sequence)
            })?;
            *out = Some(sequence_value);
        }
    }

    Ok(Understood::Yes)
}
