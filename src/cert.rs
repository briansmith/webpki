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

pub enum EndEntityOrCA<'a> {
    EndEntity,
    CA(&'a Cert<'a>),
}

pub struct Cert<'a> {
    pub ee_or_ca: EndEntityOrCA<'a>,

    pub signed_data: signed_data::SignedData<'a>,
    pub issuer: untrusted::Input<'a>,
    pub validity: untrusted::Input<'a>,
    pub subject: untrusted::Input<'a>,
    pub spki: untrusted::Input<'a>,

    pub basic_constraints: Option<untrusted::Input<'a>>,
    pub eku: Option<untrusted::Input<'a>>,
    pub name_constraints: Option<untrusted::Input<'a>>,
    pub subject_alt_name: Option<untrusted::Input<'a>>,

    // If this is true, the certificate cannot be used for anything other than
    // verifying signatures, since it has a critical extension we do not
    // understand.
    //
    // We can’t just reject the certificate at parse-time because that would prevent WebPKI for
    // being used outside of the Internet PKI. libp2p, for example, uses a critical extension that
    // webpki does not (and should not) know about.
    pub poison: bool,
}

/// The type of custom extension handling callbacks.
///
/// These will be called for each extension that WebPKI cannot handle itself.
/// Return [`Understood::Yes`] if the extension is understood, or
/// [`Understood::No`] otherwise.
pub trait ExtensionHandler<'a> {
    /// Check if the extension is understood.
    fn understood(
        &mut self, oid: untrusted::Input<'a>, value: untrusted::Input<'a>, critical: bool,
        spki: untrusted::Input<'a>,
    ) -> Understood;
}

impl<'a, T> ExtensionHandler<'a> for T
where
    T: FnMut(untrusted::Input<'a>, untrusted::Input<'a>, bool, untrusted::Input<'a>) -> Understood,
{
    fn understood(
        &mut self, oid: untrusted::Input<'a>, value: untrusted::Input<'a>, critical: bool,
        spki: untrusted::Input<'a>,
    ) -> Understood {
        self(oid, value, critical, spki)
    }
}

pub fn parse_cert<'a>(
    cert_der: untrusted::Input<'a>, ee_or_ca: EndEntityOrCA<'a>,
    handler: Option<&mut (dyn ExtensionHandler<'a> + '_)>,
) -> Result<Cert<'a>, Error> {
    parse_cert_internal(cert_der, ee_or_ca, certificate_serial_number, handler)
}

/// Used by `parse_cert` for regular certificates (end-entity and intermediate)
/// and by `cert_der_as_trust_anchor` for trust anchors encoded as
/// certificates.
pub(crate) fn parse_cert_internal<'a>(
    cert_der: untrusted::Input<'a>, ee_or_ca: EndEntityOrCA<'a>,
    serial_number: fn(input: &mut untrusted::Reader<'_>) -> Result<(), Error>,
    mut handler: Option<&mut (dyn ExtensionHandler<'a> + '_)>,
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
        let spki = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;

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

            poison: false,
        };

        // mozilla::pkix allows the extensions to be omitted. However, since
        // the subjectAltName extension is mandatory, the extensions are
        // mandatory too, and we enforce that. Also, mozilla::pkix includes
        // special logic for handling critical Netscape Cert Type extensions.
        // That has been intentionally omitted.

        der::nested_mut(
            tbs,
            der::Tag::ContextSpecificConstructed3,
            Error::BadDER,
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
                        let understood = match (
                            remember_extension(&mut cert, extn_id, extn_value)?,
                            handler.as_deref_mut(),
                        ) {
                            (e @ Understood::Yes, _) => e,
                            (Understood::No, None) => Understood::No,
                            (Understood::No, Some(handler)) =>
                                handler.understood(extn_id, extn_value, critical, spki),
                        };
                        match understood {
                            Understood::No => cert.poison |= critical,
                            Understood::Yes => {},
                        }
                        Ok(())
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
        Error::BadDER,
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

/// Whether a given certificate extension was understood.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Understood {
    /// The extension was understood.
    Yes,
    /// The extension was not understood. If the certificate is critical,
    /// and we are validating the certificate, it will be rejected. The only
    /// operations that do not validate the certificate are `verify_signature`
    /// and `cert_der_as_trust_anchor`.
    No,
}

fn remember_extension<'a>(
    cert: &mut Cert<'a>, extn_id: untrusted::Input, value: untrusted::Input<'a>,
) -> Result<Understood, Error> {
    // We don't do anything with certificate policies so we can safely ignore
    // all policy-related stuff. We assume that the policy-related extensions
    // are not marked critical.

    // id-ce 2.5.29
    static ID_CE: [u8; 2] = oid![2, 5, 29];

    if extn_id.len() != ID_CE.len() + 1 || !extn_id.as_slice_less_safe().starts_with(&ID_CE) {
        return Ok(Understood::No);
    }

    let out = match *extn_id.as_slice_less_safe().last().unwrap() {
        // id-ce-keyUsage 2.5.29.15. We ignore the KeyUsage extension. For CA
        // certificates, BasicConstraints.cA makes KeyUsage redundant. Firefox
        // and other common browsers do not check KeyUsage for end-entities,
        // though it would be kind of nice to ensure that a KeyUsage without
        // the keyEncipherment bit could not be used for RSA key exchange.
        15 => {
            return Ok(Understood::Yes);
        },

        // id-ce-subjectAltName 2.5.29.17
        17 => &mut cert.subject_alt_name,

        // id-ce-basicConstraints 2.5.29.19
        19 => &mut cert.basic_constraints,

        // id-ce-nameConstraints 2.5.29.30
        30 => &mut cert.name_constraints,

        // id-ce-extKeyUsage 2.5.29.37
        37 => &mut cert.eku,

        _ => {
            return Ok(Understood::No);
        },
    };

    match *out {
        Some(..) => {
            // The certificate contains more than one instance of this
            // extension.
            return Err(Error::ExtensionValueInvalid);
        },
        None => {
            // All the extensions that we care about are wrapped in a SEQUENCE.
            let sequence_value = value.read_all(Error::BadDER, |value| {
                der::expect_tag_and_get_value(value, der::Tag::Sequence)
            })?;
            *out = Some(sequence_value);
        },
    }

    Ok(Understood::Yes)
}
