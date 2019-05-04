// Copyright 2016 Joseph Birr-Pixton.
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

#![deny(box_pointers)]
#![forbid(
    anonymous_parameters,
    legacy_directory_ownership,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    variant_size_differences,
    warnings
)]

#[cfg(feature = "trust_anchor_util")]
extern crate untrusted;

#[cfg(any(feature = "std", feature = "trust_anchor_util"))]
extern crate webpki;

#[cfg(feature = "trust_anchor_util")]
static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
    &webpki::ED25519,
];

/* Checks we can verify netflix's cert chain.  This is notable
 * because they're rooted at a Verisign v1 root. */
#[allow(box_pointers)]
#[cfg(feature = "trust_anchor_util")]
#[test]
pub fn netflix() {
    let ee = include_bytes!("netflix/ee.der");
    let inter = include_bytes!("netflix/inter.der");
    let ca = include_bytes!("netflix/ca.der");

    let ee_input = untrusted::Input::from(ee);
    let inter_vec = vec![untrusted::Input::from(inter)];
    let anchors =
        vec![
            webpki::trust_anchor_util::cert_der_as_trust_anchor(untrusted::Input::from(ca))
                .unwrap(),
        ];
    let anchors = webpki::TLSServerTrustAnchors(&anchors);

    let time = webpki::Time::from_seconds_since_unix_epoch(1492441716);

    let cert = webpki::EndEntityCert::from(ee_input).unwrap();
    let _ = cert
        .verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &inter_vec, time)
        .unwrap();
}

#[cfg(feature = "trust_anchor_util")]
#[test]
pub fn ed25519() {
    let ee = include_bytes!("ed25519/ee.der");
    let ca = include_bytes!("ed25519/ca.der");

    let ee_input = untrusted::Input::from(ee);
    let anchors =
        vec![
            webpki::trust_anchor_util::cert_der_as_trust_anchor(untrusted::Input::from(ca))
                .unwrap(),
        ];
    let anchors = webpki::TLSServerTrustAnchors(&anchors);

    let time = webpki::Time::from_seconds_since_unix_epoch(1547363522);

    let cert = webpki::EndEntityCert::from(ee_input).unwrap();
    let _ = cert
        .verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[], time)
        .unwrap();
}

#[cfg(feature = "trust_anchor_util")]
#[test]
fn read_root_with_zero_serial() {
    let ca = include_bytes!("misc/serial_zero.der");
    let _ = webpki::trust_anchor_util::cert_der_as_trust_anchor(untrusted::Input::from(ca))
        .expect("godaddy cert should parse as anchor");
}

#[cfg(feature = "trust_anchor_util")]
#[test]
fn read_root_with_neg_serial() {
    let ca = include_bytes!("misc/serial_neg.der");
    let _ = webpki::trust_anchor_util::cert_der_as_trust_anchor(untrusted::Input::from(ca))
        .expect("idcat cert should parse as anchor");
}

#[cfg(feature = "std")]
#[test]
fn time_constructor() { let _ = webpki::Time::try_from(std::time::SystemTime::now()).unwrap(); }

#[cfg(feature = "trust_anchor_util")]
mod expiry {
    use untrusted::Input;
    use webpki::{trust_anchor_util, EndEntityCert, Error};

    fn expect_expiry(when: u64, ee: &[u8], expect_err: Option<Error>) {
        let ca = include_bytes!("expiry/ca.der");

        let ee_input = Input::from(ee);
        let inter_vec = vec![];
        let anchors = [trust_anchor_util::cert_der_as_trust_anchor(Input::from(ca)).unwrap()];
        let anchors = webpki::TLSServerTrustAnchors(&anchors);

        let rough_time = webpki::Time::from_seconds_since_unix_epoch(when);

        let cert = EndEntityCert::from(ee_input).unwrap();
        let rc = cert.verify_is_valid_tls_server_cert(
            super::ALL_SIGALGS,
            &anchors,
            &inter_vec,
            rough_time,
        );

        assert_eq!(expect_err, rc.err());
    }

    #[test]
    pub fn valid() {
        let cert = include_bytes!("expiry/ee.der");
        expect_expiry(1479496432, &cert[..], None);
    }

    #[test]
    pub fn ee_not_valid_yet() {
        let cert = include_bytes!("expiry/ee.der");
        expect_expiry(1476731633, &cert[..], None);
        expect_expiry(1476731632, &cert[..], Some(Error::CertNotValidYet));
    }

    #[test]
    pub fn ee_expired() {
        let cert = include_bytes!("expiry/ee.der");
        expect_expiry(1479496433, &cert[..], None);
        expect_expiry(1479496434, &cert[..], Some(Error::CertExpired));
    }

    #[test]
    fn ca_not_valid_yet() {
        let cert = include_bytes!("expiry/eelong.der");
        expect_expiry(1476731623, &cert[..], None);
        expect_expiry(1476731622, &cert[..], Some(Error::UnknownIssuer));
    }

    #[test]
    fn ca_expired() {
        // This certificate has an expiry that extends past the end
        // of its CA cert.
        let cert = include_bytes!("expiry/eelong.der");
        expect_expiry(1508267623, &cert[..], None);
        expect_expiry(1508267624, &cert[..], Some(Error::UnknownIssuer));
    }
}
