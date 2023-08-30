// Copyright 2015-2021 Brian Smith.
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
    cert, name, signed_data, verify_cert, DnsNameRef, Error, SignatureAlgorithm, Time,
    TlsClientTrustAnchors, TlsServerTrustAnchors,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// An end-entity certificate.
///
/// Server certificate processing in a TLS connection consists of several
/// steps. All of these steps are necessary:
///
/// * `EndEntityCert.verify_is_valid_tls_server_cert`: Verify that the server's
///   certificate is currently valid *for use by a TLS server*.
/// * `EndEntityCert.verify_is_valid_for_dns_name`: Verify that the server's
///   certificate is valid for the host that is being connected to.
/// * `EndEntityCert.verify_signature`: Verify that the signature of server's
///   `ServerKeyExchange` message is valid for the server's certificate.
///
/// Client certificate processing in a TLS connection consists of analogous
/// steps. All of these steps are necessary:
///
/// * `EndEntityCert.verify_is_valid_tls_client_cert`: Verify that the client's
///   certificate is currently valid *for use by a TLS client*.
/// * `EndEntityCert.verify_is_valid_for_dns_name` or
///   `EndEntityCert.verify_is_valid_for_at_least_one_dns_name`: Verify that the
///   client's certificate is valid for the identity or identities used to
///   identify the client. (Currently client authentication only works when the
///   client is identified by one or more DNS hostnames.)
/// * `EndEntityCert.verify_signature`: Verify that the client's signature in
///   its `CertificateVerify` message is valid using the public key from the
///   client's certificate.
///
/// Although it would be less error-prone to combine all these steps into a
/// single function call, some significant optimizations are possible if the
/// three steps are processed separately (in parallel). It does not matter much
/// which order the steps are done in, but **all of these steps must completed
/// before application data is sent and before received application data is
/// processed**. `EndEntityCert::from` is an inexpensive operation and is
/// deterministic, so if these tasks are done in multiple threads, it is
/// probably best to just call `EndEntityCert::from` multiple times (before each
/// operation) for the same DER-encoded ASN.1 certificate bytes.
pub struct EndEntityCert<'a> {
    inner: cert::Cert<'a>,
}

impl<'a> core::convert::TryFrom<&'a [u8]> for EndEntityCert<'a> {
    type Error = Error;

    /// Parse the ASN.1 DER-encoded X.509 encoding of the certificate
    /// `cert_der`.
    fn try_from(cert_der: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: cert::parse_cert(
                untrusted::Input::from(cert_der),
                cert::EndEntityOrCa::EndEntity,
            )?,
        })
    }
}

impl<'a> EndEntityCert<'a> {
    pub(super) fn inner(&self) -> &cert::Cert {
        &self.inner
    }

    /// Verifies that the end-entity certificate is valid for use by a TLS
    /// server.
    ///
    /// `supported_sig_algs` is the list of signature algorithms that are
    /// trusted for use in certificate signatures; the end-entity certificate's
    /// public key is not validated against this list. `trust_anchors` is the
    /// list of root CAs to trust. `intermediate_certs` is the sequence of
    /// intermediate certificates that the server sent in the TLS handshake.
    /// `time` is the time for which the validation is effective (usually the
    /// current time).
    pub fn verify_is_valid_tls_server_cert(
        &self,
        supported_sig_algs: &[&SignatureAlgorithm],
        &TlsServerTrustAnchors(trust_anchors): &TlsServerTrustAnchors,
        intermediate_certs: &[&[u8]],
        time: Time,
    ) -> Result<(), Error> {
        verify_cert::build_chain(
            verify_cert::EKU_SERVER_AUTH,
            supported_sig_algs,
            trust_anchors,
            intermediate_certs,
            &self.inner,
            time,
            0,
        )
    }

    /// Verifies that the end-entity certificate is valid for use by a TLS
    /// client.
    ///
    /// If the certificate is not valid for any of the given names then this
    /// fails with `Error::CertNotValidForName`.
    ///
    /// `supported_sig_algs` is the list of signature algorithms that are
    /// trusted for use in certificate signatures; the end-entity certificate's
    /// public key is not validated against this list. `trust_anchors` is the
    /// list of root CAs to trust. `intermediate_certs` is the sequence of
    /// intermediate certificates that the client sent in the TLS handshake.
    /// `cert` is the purported end-entity certificate of the client. `time` is
    /// the time for which the validation is effective (usually the current
    /// time).
    pub fn verify_is_valid_tls_client_cert(
        &self,
        supported_sig_algs: &[&SignatureAlgorithm],
        &TlsClientTrustAnchors(trust_anchors): &TlsClientTrustAnchors,
        intermediate_certs: &[&[u8]],
        time: Time,
    ) -> Result<(), Error> {
        verify_cert::build_chain(
            verify_cert::EKU_CLIENT_AUTH,
            supported_sig_algs,
            trust_anchors,
            intermediate_certs,
            &self.inner,
            time,
            0,
        )
    }

    /// Verifies that the certificate is valid for the given DNS host name.
    pub fn verify_is_valid_for_dns_name(&self, dns_name: DnsNameRef) -> Result<(), Error> {
        name::verify_cert_dns_name(&self, dns_name)
    }

    /// Verifies that the certificate is valid for at least one of the given DNS
    /// host names.
    ///
    /// If the certificate is not valid for any of the given names then this
    /// fails with `Error::CertNotValidForName`. Otherwise the DNS names for
    /// which the certificate is valid are returned.
    ///
    /// Requires the `alloc` default feature; i.e. this isn't available in
    /// `#![no_std]` configurations.
    #[cfg(feature = "alloc")]
    pub fn verify_is_valid_for_at_least_one_dns_name<'names, Names>(
        &self,
        dns_names: Names,
    ) -> Result<Vec<DnsNameRef<'names>>, Error>
    where
        Names: Iterator<Item = DnsNameRef<'names>>,
    {
        let result: Vec<DnsNameRef<'names>> = dns_names
            .filter(|n| self.verify_is_valid_for_dns_name(*n).is_ok())
            .collect();
        if result.is_empty() {
            return Err(Error::CertNotValidForName);
        }
        Ok(result)
    }

    /// Verifies the signature `signature` of message `msg` using the
    /// certificate's public key.
    ///
    /// `signature_alg` is the algorithm to use to
    /// verify the signature; the certificate's public key is verified to be
    /// compatible with this algorithm.
    ///
    /// For TLS 1.2, `signature` corresponds to TLS's
    /// `DigitallySigned.signature` and `signature_alg` corresponds to TLS's
    /// `DigitallySigned.algorithm` of TLS type `SignatureAndHashAlgorithm`. In
    /// TLS 1.2 a single `SignatureAndHashAlgorithm` may map to multiple
    /// `SignatureAlgorithm`s. For example, a TLS 1.2
    /// `ignatureAndHashAlgorithm` of (ECDSA, SHA-256) may map to any or all
    /// of {`ECDSA_P256_SHA256`, `ECDSA_P384_SHA256`}, depending on how the TLS
    /// implementation is configured.
    ///
    /// For current TLS 1.3 drafts, `signature_alg` corresponds to TLS's
    /// `algorithm` fields of type `SignatureScheme`. There is (currently) a
    /// one-to-one correspondence between TLS 1.3's `SignatureScheme` and
    /// `SignatureAlgorithm`.
    pub fn verify_signature(
        &self,
        signature_alg: &SignatureAlgorithm,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        signed_data::verify_signature(
            signature_alg,
            self.inner.spki.value(),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature),
        )
    }
}
