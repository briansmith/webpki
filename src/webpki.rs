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
    InvalidCertValidity,
    InvalidReferenceName,
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FatalError {
    ImpossibleState,
    InvalidTrustAnchor,
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
