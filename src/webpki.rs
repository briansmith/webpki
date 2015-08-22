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

mod cert;
mod der;
mod name;
mod input;
mod signed_data;
mod verify_cert;

pub use input::Input;
pub use name::verify_cert_dns_name;

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

pub struct TrustAnchor<'a> {
    pub subject: &'a [u8],
    pub spki: &'a [u8],
    pub name_constraints: Option<&'a [u8]>
}
