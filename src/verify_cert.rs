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

use crate::{
    cert::{self, Cert, EndEntityOrCa},
    der, name, signed_data, time, Error, SignatureAlgorithm, TrustAnchor,
};

pub fn build_chain(
    required_eku_if_present: KeyPurposeId,
    supported_sig_algs: &[&SignatureAlgorithm],
    trust_anchors: &[TrustAnchor],
    intermediate_certs: &[&[u8]],
    cert: &Cert,
    time: time::Time,
) -> Result<(), Error> {
    let result = build_chain_inner(
        required_eku_if_present,
        supported_sig_algs,
        trust_anchors,
        intermediate_certs,
        cert,
        time,
        0,
        &mut 0,
    );
    result.map_err(|error| {
        match error {
            ErrorOrInternalError::Error(e) => e,
            // Eat internal errors,
            ErrorOrInternalError::InternalError(_) => Error::UnknownIssuer,
        }
    })
}

/// Errors that we cannot report externally since `Error` wasn't declared
/// non-exhaustive, but which we need to differentiate internally (at least
/// for testing).
enum InternalError {
    MaximumSignatureChecksExceeded,
}

enum ErrorOrInternalError {
    Error(Error),
    InternalError(InternalError),
}

impl ErrorOrInternalError {
    fn is_fatal(&self) -> bool {
        match self {
            ErrorOrInternalError::Error(_) => false,
            ErrorOrInternalError::InternalError(InternalError::MaximumSignatureChecksExceeded) => {
                true
            }
        }
    }
}

impl From<InternalError> for ErrorOrInternalError {
    fn from(value: InternalError) -> Self {
        Self::InternalError(value)
    }
}

impl From<Error> for ErrorOrInternalError {
    fn from(error: Error) -> Self {
        Self::Error(error)
    }
}

fn build_chain_inner(
    required_eku_if_present: KeyPurposeId,
    supported_sig_algs: &[&SignatureAlgorithm],
    trust_anchors: &[TrustAnchor],
    intermediate_certs: &[&[u8]],
    cert: &Cert,
    time: time::Time,
    sub_ca_count: usize,
    signatures: &mut usize,
) -> Result<(), ErrorOrInternalError> {
    let used_as_ca = used_as_ca(&cert.ee_or_ca);

    check_issuer_independent_properties(
        cert,
        time,
        used_as_ca,
        sub_ca_count,
        required_eku_if_present,
    )?;

    // TODO: HPKP checks.

    match used_as_ca {
        UsedAsCa::Yes => {
            const MAX_SUB_CA_COUNT: usize = 6;

            if sub_ca_count >= MAX_SUB_CA_COUNT {
                return Err(Error::UnknownIssuer.into());
            }
        }
        UsedAsCa::No => {
            assert_eq!(0, sub_ca_count);
        }
    }

    // TODO: revocation.

    match loop_while_non_fatal_error(trust_anchors, |trust_anchor: &TrustAnchor| {
        let trust_anchor_subject = untrusted::Input::from(trust_anchor.subject);
        if cert.issuer != trust_anchor_subject {
            return Err(Error::UnknownIssuer.into());
        }

        let name_constraints = trust_anchor.name_constraints.map(untrusted::Input::from);

        untrusted::read_all_optional(name_constraints, Error::BadDer, |value| {
            name::check_name_constraints(value, &cert)
        })?;

        let trust_anchor_spki = untrusted::Input::from(trust_anchor.spki);

        // TODO: check_distrust(trust_anchor_subject, trust_anchor_spki)?;

        check_signatures(supported_sig_algs, cert, trust_anchor_spki, signatures)?;

        Ok(())
    }) {
        Ok(()) => {
            return Ok(());
        }
        Err(e) => {
            if e.is_fatal() {
                return Err(e);
            }
            // If the error is not fatal, then keep going.
        }
    }

    loop_while_non_fatal_error(intermediate_certs, |cert_der| {
        let potential_issuer =
            cert::parse_cert(untrusted::Input::from(*cert_der), EndEntityOrCa::Ca(&cert))?;

        if potential_issuer.subject != cert.issuer {
            return Err(Error::UnknownIssuer.into());
        }

        // Prevent loops; see RFC 4158 section 5.2.
        let mut prev = cert;
        loop {
            if potential_issuer.spki.value() == prev.spki.value()
                && potential_issuer.subject == prev.subject
            {
                return Err(Error::UnknownIssuer.into());
            }
            match &prev.ee_or_ca {
                EndEntityOrCa::EndEntity => {
                    break;
                }
                EndEntityOrCa::Ca(child_cert) => {
                    prev = child_cert;
                }
            }
        }

        untrusted::read_all_optional(potential_issuer.name_constraints, Error::BadDer, |value| {
            name::check_name_constraints(value, &cert)
        })?;

        let next_sub_ca_count = match used_as_ca {
            UsedAsCa::No => sub_ca_count,
            UsedAsCa::Yes => sub_ca_count + 1,
        };

        build_chain_inner(
            required_eku_if_present,
            supported_sig_algs,
            trust_anchors,
            intermediate_certs,
            &potential_issuer,
            time,
            next_sub_ca_count,
            signatures,
        )
    })
}

fn check_signatures(
    supported_sig_algs: &[&SignatureAlgorithm],
    cert_chain: &Cert,
    trust_anchor_key: untrusted::Input,
    signatures: &mut usize,
) -> Result<(), ErrorOrInternalError> {
    let mut spki_value = trust_anchor_key;
    let mut cert = cert_chain;
    loop {
        *signatures += 1;
        if *signatures > 100 {
            return Err(InternalError::MaximumSignatureChecksExceeded.into());
        }

        signed_data::verify_signed_data(supported_sig_algs, spki_value, &cert.signed_data)?;

        // TODO: check revocation

        match &cert.ee_or_ca {
            EndEntityOrCa::Ca(child_cert) => {
                spki_value = cert.spki.value();
                cert = child_cert;
            }
            EndEntityOrCa::EndEntity => {
                break;
            }
        }
    }

    Ok(())
}

fn check_issuer_independent_properties(
    cert: &Cert,
    time: time::Time,
    used_as_ca: UsedAsCa,
    sub_ca_count: usize,
    required_eku_if_present: KeyPurposeId,
) -> Result<(), Error> {
    // TODO: check_distrust(trust_anchor_subject, trust_anchor_spki)?;
    // TODO: Check signature algorithm like mozilla::pkix.
    // TODO: Check SPKI like mozilla::pkix.
    // TODO: check for active distrust like mozilla::pkix.

    // See the comment in `remember_extension` for why we don't check the
    // KeyUsage extension.

    cert.validity
        .read_all(Error::BadDer, |value| check_validity(value, time))?;
    untrusted::read_all_optional(cert.basic_constraints, Error::BadDer, |value| {
        check_basic_constraints(value, used_as_ca, sub_ca_count)
    })?;
    untrusted::read_all_optional(cert.eku, Error::BadDer, |value| {
        check_eku(value, required_eku_if_present)
    })?;

    Ok(())
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.5
fn check_validity(input: &mut untrusted::Reader, time: time::Time) -> Result<(), Error> {
    let not_before = der::time_choice(input)?;
    let not_after = der::time_choice(input)?;

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
enum UsedAsCa {
    Yes,
    No,
}

fn used_as_ca(ee_or_ca: &EndEntityOrCa) -> UsedAsCa {
    match ee_or_ca {
        EndEntityOrCa::EndEntity => UsedAsCa::No,
        EndEntityOrCa::Ca(..) => UsedAsCa::Yes,
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
fn check_basic_constraints(
    input: Option<&mut untrusted::Reader>,
    used_as_ca: UsedAsCa,
    sub_ca_count: usize,
) -> Result<(), Error> {
    let (is_ca, path_len_constraint) = match input {
        Some(input) => {
            let is_ca = der::optional_boolean(input)?;

            // https://bugzilla.mozilla.org/show_bug.cgi?id=985025: RFC 5280
            // says that a certificate must not have pathLenConstraint unless
            // it is a CA certificate, but some real-world end-entity
            // certificates have pathLenConstraint.
            let path_len_constraint = if !input.at_end() {
                let value = der::small_nonnegative_integer(input)?;
                Some(usize::from(value))
            } else {
                None
            };

            (is_ca, path_len_constraint)
        }
        None => (false, None),
    };

    match (used_as_ca, is_ca, path_len_constraint) {
        (UsedAsCa::No, true, _) => Err(Error::CaUsedAsEndEntity),
        (UsedAsCa::Yes, false, _) => Err(Error::EndEntityUsedAsCa),
        (UsedAsCa::Yes, true, Some(len)) if sub_ca_count > len => {
            Err(Error::PathLenConstraintViolated)
        }
        _ => Ok(()),
    }
}

#[derive(Clone, Copy)]
pub struct KeyPurposeId {
    oid_value: untrusted::Input<'static>,
}

// id-pkix            OBJECT IDENTIFIER ::= { 1 3 6 1 5 5 7 }
// id-kp              OBJECT IDENTIFIER ::= { id-pkix 3 }

// id-kp-serverAuth   OBJECT IDENTIFIER ::= { id-kp 1 }
#[allow(clippy::identity_op)] // TODO: Make this clearer
pub static EKU_SERVER_AUTH: KeyPurposeId = KeyPurposeId {
    oid_value: untrusted::Input::from(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 1]),
};

// id-kp-clientAuth   OBJECT IDENTIFIER ::= { id-kp 2 }
#[allow(clippy::identity_op)] // TODO: Make this clearer
pub static EKU_CLIENT_AUTH: KeyPurposeId = KeyPurposeId {
    oid_value: untrusted::Input::from(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 2]),
};

// id-kp-OCSPSigning  OBJECT IDENTIFIER ::= { id-kp 9 }
#[allow(clippy::identity_op)] // TODO: Make this clearer
pub static EKU_OCSP_SIGNING: KeyPurposeId = KeyPurposeId {
    oid_value: untrusted::Input::from(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 9]),
};

// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
//
// Notable Differences from RFC 5280:
//
// * We follow the convention established by Microsoft's implementation and
//   mozilla::pkix of treating the EKU extension in a CA certificate as a
//   restriction on the allowable EKUs for certificates issued by that CA. RFC
//   5280 doesn't prescribe any meaning to the EKU extension when a certificate
//   is being used as a CA certificate.
//
// * We do not recognize anyExtendedKeyUsage. NSS and mozilla::pkix do not
//   recognize it either.
//
// * We treat id-Netscape-stepUp as being equivalent to id-kp-serverAuth in CA
//   certificates (only). Comodo has issued certificates that require this
//   behavior that don't expire until June 2020. See https://bugzilla.mozilla.org/show_bug.cgi?id=982292.
fn check_eku(
    input: Option<&mut untrusted::Reader>,
    required_eku_if_present: KeyPurposeId,
) -> Result<(), Error> {
    match input {
        Some(input) => {
            loop {
                let value = der::expect_tag_and_get_value(input, der::Tag::OID)?;
                if value == required_eku_if_present.oid_value {
                    input.skip_to_end();
                    break;
                }
                if input.at_end() {
                    return Err(Error::RequiredEkuNotFound);
                }
            }
            Ok(())
        }
        None => {
            // http://tools.ietf.org/html/rfc6960#section-4.2.2.2:
            // "OCSP signing delegation SHALL be designated by the inclusion of
            // id-kp-OCSPSigning in an extended key usage certificate extension
            // included in the OCSP response signer's certificate."
            //
            // A missing EKU extension generally means "any EKU", but it is
            // important that id-kp-OCSPSigning is explicit so that a normal
            // end-entity certificate isn't able to sign trusted OCSP responses
            // for itself or for other certificates issued by its issuing CA.
            if required_eku_if_present.oid_value == EKU_OCSP_SIGNING.oid_value {
                return Err(Error::RequiredEkuNotFound);
            }

            Ok(())
        }
    }
}

fn loop_while_non_fatal_error<V>(
    values: V,
    mut f: impl FnMut(V::Item) -> Result<(), ErrorOrInternalError>,
) -> Result<(), ErrorOrInternalError>
where
    V: IntoIterator,
{
    for v in values {
        match f(v) {
            Ok(()) => {
                return Ok(());
            }
            Err(e) => {
                if e.is_fatal() {
                    return Err(e);
                }
                // If the error is not fatal, then keep going.
            }
        }
    }
    Err(Error::UnknownIssuer.into())
}

#[cfg(test)]
mod tests {

    #[test]
    #[cfg(feature = "alloc")]
    fn test_too_many_signatures() {
        use super::*;
        use crate::ECDSA_P256_SHA256;
        use crate::{EndEntityCert, Time};
        use alloc::{string::ToString, vec::Vec};
        use core::convert::TryFrom;

        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;

        let make_issuer = || {
            let mut ca_params = rcgen::CertificateParams::new(Vec::new());
            ca_params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "Bogus Subject");
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            ca_params.alg = alg;
            rcgen::Certificate::from_params(ca_params).unwrap()
        };

        let ca_cert = make_issuer();
        let ca_cert_der = ca_cert.serialize_der().unwrap();

        let mut intermediates = Vec::with_capacity(101);
        let mut issuer = ca_cert;
        for _ in 0..101 {
            let intermediate = make_issuer();
            let intermediate_der = intermediate.serialize_der_with_signer(&issuer).unwrap();
            intermediates.push(intermediate_der);
            issuer = intermediate;
        }

        let mut ee_params = rcgen::CertificateParams::new(vec!["example.com".to_string()]);
        ee_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        ee_params.alg = alg;
        let ee_cert = rcgen::Certificate::from_params(ee_params).unwrap();
        let ee_cert_der = ee_cert.serialize_der_with_signer(&issuer).unwrap();

        let anchors = &[TrustAnchor::try_from_cert_der(&ca_cert_der).unwrap()];
        let time = Time::from_seconds_since_unix_epoch(0x1fed_f00d);
        let cert = EndEntityCert::try_from(&ee_cert_der[..]).unwrap();
        let intermediates_der: Vec<&[u8]> = intermediates.iter().map(|x| x.as_ref()).collect();
        let intermediate_certs: &[&[u8]] = intermediates_der.as_ref();

        // TODO: Use `build_chain` when `Error` is made non-exhaustive.
        let result = build_chain_inner(
            EKU_SERVER_AUTH,
            &[&ECDSA_P256_SHA256],
            anchors,
            intermediate_certs,
            cert.inner(),
            time,
            0,
            &mut 0,
        );

        assert!(matches!(
            result,
            Err(ErrorOrInternalError::InternalError(
                InternalError::MaximumSignatureChecksExceeded
            ))
        ));
    }
}
