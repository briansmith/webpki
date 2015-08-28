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

use std::error;
use std::fmt;

extern crate ring;
extern crate time;

#[cfg(test)]
extern crate rustc_serialize;

pub mod input;
pub mod trust_anchor_util;

mod cert;
mod der;
mod name;
mod signed_data;
mod verify_cert;

pub use input::Input;
pub use name::verify_cert_dns_name;
pub use verify_cert::verify_tls_cert;

pub enum PublicKey<'a> {
    EC(Input<'a>, &'static ring::EllipticCurve),
    RSA(Input<'a>)
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    BadDER,
    BadDERTime,
    BadSignature,
    CAUsedAsEndEntity,
    CertExpired,
    CertNotValidForName,
    CertNotValidYet,
    EndEntityUsedAsCA,
    ExtensionValueInvalid,
    Fatal(FatalError),
    InvalidReferenceName,
    InvalidValidityPeriod,
    NameConstraintViolation,
    PathLenConstraintViolated,
    SignatureAlgorithmMismatch,
    RequiredEKUNotFound,
    UnknownIssuer,
    UnsupportedCertVersion,
    UnsupportedCriticalExtension,
    UnsupportedEllipticCurve,
    UnsupportedKeyAlgorithm,
    UnsupportedSignatureAlgorithm,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;
        writeln!(f, "{}", self.description())
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::BadDER => "Certificate has improperly formatted DER-encoded message",
            Error::BadDERTime => "Certificate's DER-encoded message contains an improperly formatted timestamp",
            Error::BadSignature => "Certificate has an invalid signature",
            Error::CAUsedAsEndEntity => "CA incorrectly used as an end entity",
            Error::CertExpired => "Certificate is expired",
            Error::CertNotValidForName => "Certificate does not match hostname",
            Error::CertNotValidYet => "Certificate is not yet valid",
            Error::EndEntityUsedAsCA => "End entity incorrectly used as a CA",
            Error::ExtensionValueInvalid => "Certificate has an invalid value for extension",
            Error::Fatal(ref fatal_error) => fatal_error.description(),
            Error::InvalidReferenceName => "Certificate has an invalid reference name",
            Error::InvalidValidityPeriod => "Certificate has an invalid validity period",
            Error::NameConstraintViolation => "Certificate has a name constraint violation",
            Error::PathLenConstraintViolated => "Certificate exceeds constraint for number of intermediate certificates",
            Error::SignatureAlgorithmMismatch => "Encountered mismatched signature algorithms",
            Error::RequiredEKUNotFound => "Certificate is missing an EKU, despite it being required",
            Error::UnknownIssuer => "Certificate issuer is unknown",
            Error::UnsupportedCertVersion => "Certificate has an unsupported version",
            Error::UnsupportedCriticalExtension => "Certificate has an unsupported critical extension",
            Error::UnsupportedEllipticCurve => "Certificate uses an unsupported elliptic curve",
            Error::UnsupportedKeyAlgorithm => "Certificate uses an unsupported key algorithm",
            Error::UnsupportedSignatureAlgorithm => "Certificate uses an unsupported signature algorithm",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FatalError {
    ImpossibleState,
    InvalidTrustAnchor,
}

impl fmt::Display for FatalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;
        writeln!(f, "{}", self.description())
    }
}

impl error::Error for FatalError {
    fn description(&self) -> &str {
        match *self {
            FatalError::ImpossibleState => "Reading certificate results in an impossible state",
            FatalError::InvalidTrustAnchor => "Certificate contains invalid trust anchor",
        }
    }
}

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
    pub subject: &'a [u8],
    pub spki: &'a [u8],
    pub name_constraints: Option<&'a [u8]>
}
