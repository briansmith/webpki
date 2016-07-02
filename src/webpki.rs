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

#![no_std]

#[cfg(any(test, feature = "trust_anchor_util"))]
#[macro_use(format)]
extern crate std;

extern crate ring;
extern crate time;

#[cfg(test)]
extern crate rustc_serialize;

extern crate untrusted;

#[macro_use]
mod der;

mod cert;
mod name;
mod signed_data;

#[cfg(feature = "trust_anchor_util")]
pub mod trust_anchor_util;

mod verify_cert;

pub use signed_data::{
    SignatureAlgorithm,
    ECDSA_P256_SHA1,
    ECDSA_P256_SHA256,
    ECDSA_P256_SHA384,
    ECDSA_P256_SHA512,
    ECDSA_P384_SHA1,
    ECDSA_P384_SHA256,
    ECDSA_P384_SHA384,
    ECDSA_P384_SHA512,
    RSA_PKCS1_SHA1_2048_8192,
    RSA_PKCS1_SHA256_2048_8192,
    RSA_PKCS1_SHA384_2048_8192,
    RSA_PKCS1_SHA512_2048_8192,
    RSA_PKCS1_SHA384_3072_8192,
};
pub use name::verify_cert_dns_name;
pub use verify_cert::verify_tls_cert;

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
    UnsupportedKeyAlgorithmForSignature,
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
