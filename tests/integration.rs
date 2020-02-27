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

    let anchors = vec![webpki::trust_anchor_util::cert_der_as_trust_anchor(ca).unwrap()];
    let anchors = webpki::TLSServerTrustAnchors(&anchors);

    let time = webpki::Time::from_seconds_since_unix_epoch(1492441716);

    let cert = webpki::EndEntityCert::from(ee).unwrap();
    let _ = cert
        .verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[inter], time)
        .unwrap();
}

/* Checks that we don’t barf too soon on bad extensions */
#[test]
#[cfg(feature = "trust_anchor_util")]
pub fn unknown_extension() {
    let crt = include_bytes!("misc/testing.crt");
    let signature = include_bytes!("misc/testing.sig");
    let data = include_bytes!("misc/gen-bad-cert.sh");
    let ca = include_bytes!("misc/ca.crt");
    let anchors = vec![webpki::trust_anchor_util::cert_der_as_trust_anchor(ca)
        .expect("parsing a certificate for a trust anchor ignores extensions")];
    let server_anchors = webpki::TLSServerTrustAnchors(&anchors);
    let client_anchors = webpki::TLSClientTrustAnchors(&anchors);
    let time = webpki::Time::from_seconds_since_unix_epoch(1735689600);
    let cert = webpki::EndEntityCert::from(crt).unwrap();
    let name_ref = webpki::DNSNameRef::try_from_ascii(&b"localhost"[..]).unwrap();
    let _ = cert
        .verify_signature(&webpki::ECDSA_P256_SHA256, data, signature)
        .expect("verify_signature ignores extensions");
    let err = cert
        .verify_is_valid_tls_server_cert(&[&webpki::ED25519], &server_anchors, &[], time)
        .unwrap_err();
    assert_eq!(err, webpki::Error::UnsupportedCriticalExtension);
    let err = cert
        .verify_is_valid_tls_client_cert(&[&webpki::ED25519], &client_anchors, &[], time)
        .unwrap_err();
    assert_eq!(err, webpki::Error::UnsupportedCriticalExtension);
    assert_eq!(
        cert.verify_is_valid_for_dns_name(name_ref).unwrap_err(),
        webpki::Error::UnsupportedCriticalExtension
    );
    // test the case where the callback understands the critical extension
    let cert = webpki::EndEntityCert::from_with_extension_cb(
        crt,
        &mut |oid, _, critical, _| match (oid.as_slice_less_safe(), critical) {
            (&[85, 29, 14], false) => webpki::Understood::No,
            (&[85, 29, 35], false) => webpki::Understood::No,
            (&[43, 6, 1, 5, 5, 7, 1, 1], true) => webpki::Understood::Yes,
            _ => panic!(
                "bad oid/critical flag combo {:?}/{}",
                oid.as_slice_less_safe(),
                critical
            ),
        },
    )
    .unwrap();
    cert.verify_is_valid_tls_server_cert(&[&webpki::ED25519], &server_anchors, &[], time)
        .unwrap();
    cert.verify_is_valid_tls_client_cert(&[&webpki::ED25519], &client_anchors, &[], time)
        .unwrap();
    cert.verify_is_valid_for_dns_name(name_ref).unwrap();
    // test the case where the callback does not understand a critical extension
    let cert = webpki::EndEntityCert::from_with_extension_cb(
        crt,
        &mut |oid, _, critical, _| match (oid.as_slice_less_safe(), critical) {
            (&[85, 29, 14], false) => webpki::Understood::Yes,
            (&[85, 29, 35], false) => webpki::Understood::Yes,
            (&[43, 6, 1, 5, 5, 7, 1, 1], true) => webpki::Understood::No,
            _ => panic!(
                "bad oid/critical flag combo {:?}/{}",
                oid.as_slice_less_safe(),
                critical
            ),
        },
    )
    .unwrap();
    let _ = cert
        .verify_signature(&webpki::ECDSA_P256_SHA256, data, signature)
        .expect("verify_signature ignores extensions");
    let err = cert
        .verify_is_valid_tls_server_cert(&[&webpki::ED25519], &server_anchors, &[], time)
        .unwrap_err();
    assert_eq!(err, webpki::Error::UnsupportedCriticalExtension);
    let err = cert
        .verify_is_valid_tls_client_cert(&[&webpki::ED25519], &client_anchors, &[], time)
        .unwrap_err();
    assert_eq!(err, webpki::Error::UnsupportedCriticalExtension);
    assert_eq!(
        cert.verify_is_valid_for_dns_name(name_ref).unwrap_err(),
        webpki::Error::UnsupportedCriticalExtension
    );
}

#[cfg(feature = "trust_anchor_util")]
#[test]
pub fn ed25519() {
    let ee = include_bytes!("ed25519/ee.der");
    let ca = include_bytes!("ed25519/ca.der");

    let anchors = vec![webpki::trust_anchor_util::cert_der_as_trust_anchor(ca).unwrap()];
    let anchors = webpki::TLSServerTrustAnchors(&anchors);

    let time = webpki::Time::from_seconds_since_unix_epoch(1547363522);

    let cert = webpki::EndEntityCert::from(ee).unwrap();
    let _ = cert
        .verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[], time)
        .unwrap();
}

#[cfg(feature = "trust_anchor_util")]
#[test]
fn read_root_with_zero_serial() {
    let ca = include_bytes!("misc/serial_zero.der");
    let _ = webpki::trust_anchor_util::cert_der_as_trust_anchor(ca)
        .expect("godaddy cert should parse as anchor");
}

#[cfg(feature = "trust_anchor_util")]
#[test]
fn read_root_with_neg_serial() {
    let ca = include_bytes!("misc/serial_neg.der");
    let _ = webpki::trust_anchor_util::cert_der_as_trust_anchor(ca)
        .expect("idcat cert should parse as anchor");
}

#[cfg(feature = "std")]
#[test]
fn time_constructor() { let _ = webpki::Time::try_from(std::time::SystemTime::now()).unwrap(); }
