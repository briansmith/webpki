use crate::cert::{certificate_serial_number, Cert};
use crate::{
    cert::{parse_cert_internal, EndEntityOrCa},
    der, Error,
};

/// A trust anchor (a.k.a. root CA).
///
/// Traditionally, certificate verification libraries have represented trust
/// anchors as full X.509 root certificates. However, those certificates
/// contain a lot more data than is needed for verifying certificates. The
/// `TrustAnchor` representation allows an application to store just the
/// essential elements of trust anchors. The `webpki::trust_anchor_util` module
/// provides functions for converting X.509 certificates to to the minimized
/// `TrustAnchor` representation, either at runtime or in a build script.
#[derive(Debug)]
pub struct TrustAnchor<'a> {
    /// The value of the `subject` field of the trust anchor.
    pub subject: &'a [u8],

    /// The value of the `subjectPublicKeyInfo` field of the trust anchor.
    pub spki: &'a [u8],

    /// The value of a DER-encoded NameConstraints, containing name
    /// constraints to apply to the trust anchor, if any.
    pub name_constraints: Option<&'a [u8]>,
}

/// Trust anchors which may be used for authenticating servers.
#[derive(Debug)]
pub struct TlsServerTrustAnchors<'a>(pub &'a [TrustAnchor<'a>]);

/// Trust anchors which may be used for authenticating clients.
#[derive(Debug)]
pub struct TlsClientTrustAnchors<'a>(pub &'a [TrustAnchor<'a>]);

impl<'a> TrustAnchor<'a> {
    /// Interprets the given DER-encoded certificate as a `TrustAnchor`. The
    /// certificate is not validated. In particular, there is no check that the
    /// certificate is self-signed or even that the certificate has the cA basic
    /// constraint.
    pub fn try_from_cert_der(cert_der: &'a [u8]) -> Result<Self, Error> {
        let cert_der = untrusted::Input::from(cert_der);

        // XXX: `EndEntityOrCA::EndEntity` is used instead of `EndEntityOrCA::CA`
        // because we don't have a reference to a child cert, which is needed for
        // `EndEntityOrCA::CA`. For this purpose, it doesn't matter.
        //
        // v1 certificates will result in `Error::BadDER` because `parse_cert` will
        // expect a version field that isn't there. In that case, try to parse the
        // certificate using a special parser for v1 certificates. Notably, that
        // parser doesn't allow extensions, so there's no need to worry about
        // embedded name constraints in a v1 certificate.
        match parse_cert_internal(
            cert_der,
            EndEntityOrCa::EndEntity,
            possibly_invalid_certificate_serial_number,
        ) {
            Ok(cert) => Ok(Self::from(cert)),
            Err(Error::UnsupportedCertVersion) => parse_cert_v1(cert_der).or(Err(Error::BadDer)),
            Err(err) => Err(err),
        }
    }
}

fn possibly_invalid_certificate_serial_number(input: &mut untrusted::Reader) -> Result<(), Error> {
    // https://tools.ietf.org/html/rfc5280#section-4.1.2.2:
    // * Conforming CAs MUST NOT use serialNumber values longer than 20 octets."
    // * "The serial number MUST be a positive integer [...]"
    //
    // However, we don't enforce these constraints on trust anchors, as there
    // are widely-deployed trust anchors that violate these constraints.
    skip(input, der::Tag::Integer)
}

impl<'a> From<Cert<'a>> for TrustAnchor<'a> {
    fn from(cert: Cert<'a>) -> Self {
        Self {
            subject: cert.subject.as_slice_less_safe(),
            spki: cert.spki.value().as_slice_less_safe(),
            name_constraints: cert.name_constraints.map(|nc| nc.as_slice_less_safe()),
        }
    }
}

/// Parses a v1 certificate directly into a TrustAnchor.
fn parse_cert_v1(cert_der: untrusted::Input) -> Result<TrustAnchor, Error> {
    // X.509 Certificate: https://tools.ietf.org/html/rfc5280#section-4.1.
    cert_der.read_all(Error::BadDer, |cert_der| {
        der::nested(cert_der, der::Tag::Sequence, Error::BadDer, |cert_der| {
            let anchor = der::nested(cert_der, der::Tag::Sequence, Error::BadDer, |tbs| {
                // The version number field does not appear in v1 certificates.
                certificate_serial_number(tbs)?;

                skip(tbs, der::Tag::Sequence)?; // signature.
                skip(tbs, der::Tag::Sequence)?; // issuer.
                skip(tbs, der::Tag::Sequence)?; // validity.
                let subject = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;
                let spki = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;

                Ok(TrustAnchor {
                    subject: subject.as_slice_less_safe(),
                    spki: spki.as_slice_less_safe(),
                    name_constraints: None,
                })
            });

            // read and discard signatureAlgorithm + signature
            skip(cert_der, der::Tag::Sequence)?;
            skip(cert_der, der::Tag::BitString)?;

            anchor
        })
    })
}

fn skip(input: &mut untrusted::Reader, tag: der::Tag) -> Result<(), Error> {
    der::expect_tag_and_get_value(input, tag).map(|_| ())
}
