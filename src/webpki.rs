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

//! webpki: Web PKI X.509 Certificate Validation.
//!
//! See `EndEntityCert`'s documentation for a description of the certificate
//! processing steps necessary for a TLS connection.
//!
//! # Features
//!
//! | Feature | Description |
//! | ------- | ----------- |
//! | `alloc` | Enable features that require use of the heap. Currently all RSA signature algorithms require this feature. |
//! | `std` | Enable features that require libstd. Implies `alloc`. |

#![doc(html_root_url = "https://briansmith.org/rustdoc/")]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::single_match)]

#[cfg(any(test, feature = "alloc"))]
#[macro_use]
extern crate alloc;

#[macro_use]
mod der;

mod calendar;
mod cert;
mod end_entity;
mod error;
mod name;
mod signed_data;
mod time;

pub mod trust_anchor_util;

mod verify_cert;

pub use {
    end_entity::EndEntityCert,
    error::Error,
    name::{DnsNameRef, InvalidDnsNameError},
    signed_data::{
        SignatureAlgorithm, ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256,
        ECDSA_P384_SHA384, ED25519,
    },
    time::Time,
};

#[cfg(feature = "alloc")]
pub use {
    name::DnsName,
    signed_data::{
        RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
        RSA_PKCS1_3072_8192_SHA384, RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA384_LEGACY_KEY, RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    },
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
pub struct TLSServerTrustAnchors<'a>(pub &'a [TrustAnchor<'a>]);

/// Trust anchors which may be used for authenticating clients.
#[derive(Debug)]
pub struct TLSClientTrustAnchors<'a>(pub &'a [TrustAnchor<'a>]);
