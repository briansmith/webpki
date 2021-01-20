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

use core::convert::TryFrom;
extern crate webpki;

static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    #[cfg(feature = "alloc")]
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    #[cfg(feature = "alloc")]
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    #[cfg(feature = "alloc")]
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    #[cfg(feature = "alloc")]
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

/* Checks we can verify netflix's cert chain.  This is notable
 * because they're rooted at a Verisign v1 root. */
#[cfg(feature = "alloc")]
#[test]
pub fn netflix() {
    let ee: &[u8] = include_bytes!("netflix/ee.der");
    let inter = include_bytes!("netflix/inter.der");
    let ca = include_bytes!("netflix/ca.der");

    let anchors = vec![webpki::trust_anchor_util::cert_der_as_trust_anchor(ca).unwrap()];
    let anchors = webpki::TLSServerTrustAnchors(&anchors);

    #[allow(clippy::unreadable_literal)] // TODO: Make this clear.
    let time = webpki::Time::from_seconds_since_unix_epoch(1492441716);

    let cert = webpki::EndEntityCert::try_from(ee).unwrap();
    assert_eq!(
        Ok(()),
        cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[inter], time)
    );
}

#[test]
pub fn ed25519() {
    let ee: &[u8] = include_bytes!("ed25519/ee.der");
    let ca = include_bytes!("ed25519/ca.der");

    let anchors = vec![webpki::trust_anchor_util::cert_der_as_trust_anchor(ca).unwrap()];
    let anchors = webpki::TLSServerTrustAnchors(&anchors);

    #[allow(clippy::unreadable_literal)] // TODO: Make this clear.
    let time = webpki::Time::from_seconds_since_unix_epoch(1547363522);

    let cert = webpki::EndEntityCert::try_from(ee).unwrap();
    assert_eq!(
        Ok(()),
        cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[], time)
    );
}

#[test]
fn read_root_with_zero_serial() {
    let ca = include_bytes!("misc/serial_zero.der");
    let _ = webpki::trust_anchor_util::cert_der_as_trust_anchor(ca)
        .expect("godaddy cert should parse as anchor");
}

#[test]
fn read_root_with_neg_serial() {
    let ca = include_bytes!("misc/serial_neg.der");
    let _ = webpki::trust_anchor_util::cert_der_as_trust_anchor(ca)
        .expect("idcat cert should parse as anchor");
}

#[cfg(feature = "std")]
#[test]
fn time_constructor() {
    let _ = webpki::Time::try_from(std::time::SystemTime::now()).unwrap();
}

#[cfg(feature = "alloc")]
#[test]
pub fn list_netflix_names() {
    let ee = include_bytes!("netflix/ee.der");

    expect_cert_dns_names(
        ee,
        &[
            "account.netflix.com",
            "ca.netflix.com",
            "netflix.ca",
            "netflix.com",
            "signup.netflix.com",
            "www.netflix.ca",
            "www1.netflix.com",
            "www2.netflix.com",
            "www3.netflix.com",
            "develop-stage.netflix.com",
            "release-stage.netflix.com",
            "www.netflix.com",
        ],
    );
}

#[cfg(feature = "alloc")]
#[test]
pub fn invalid_subject_alt_names() {
    // same as netflix ee certificate, but with the last name in the list
    // changed to 'www.netflix:com'
    let data = include_bytes!("misc/invalid_subject_alternative_name.der");

    expect_cert_dns_names(
        data,
        &[
            "account.netflix.com",
            "ca.netflix.com",
            "netflix.ca",
            "netflix.com",
            "signup.netflix.com",
            "www.netflix.ca",
            "www1.netflix.com",
            "www2.netflix.com",
            "www3.netflix.com",
            "develop-stage.netflix.com",
            "release-stage.netflix.com",
            // NOT 'www.netflix:com'
        ],
    );
}

#[cfg(feature = "alloc")]
#[test]
pub fn wildcard_subject_alternative_names() {
    // same as netflix ee certificate, but with the last name in the list
    // changed to 'ww*.netflix:com'
    let data = include_bytes!("misc/dns_names_and_wildcards.der");

    expect_cert_dns_names(
        data,
        &[
            "account.netflix.com",
            "*.netflix.com",
            "netflix.ca",
            "netflix.com",
            "signup.netflix.com",
            "www.netflix.ca",
            "www1.netflix.com",
            "www2.netflix.com",
            "www3.netflix.com",
            "develop-stage.netflix.com",
            "release-stage.netflix.com",
            "www.netflix.com",
        ],
    );
}

#[cfg(feature = "alloc")]
fn expect_cert_dns_names(data: &[u8], expected_names: &[&str]) {
    use std::collections::HashSet;

    let cert = webpki::EndEntityCert::try_from(data)
        .expect("should parse end entity certificate correctly");

    let expected_names: HashSet<_> = expected_names.iter().cloned().collect();

    let mut actual_names = cert
        .dns_names()
        .expect("should get all DNS names correctly for end entity cert");

    // Ensure that converting the list to a set doesn't throw away
    // any duplicates that aren't supposed to be there
    assert_eq!(actual_names.len(), expected_names.len());

    let actual_names: std::collections::HashSet<&str> =
        actual_names.drain(..).map(|name| name.into()).collect();

    assert_eq!(actual_names, expected_names);
}

#[cfg(feature = "alloc")]
#[test]
pub fn no_subject_alt_names() {
    let data = include_bytes!("misc/no_subject_alternative_name.der");

    let cert = webpki::EndEntityCert::try_from(&data[..])
        .expect("should parse end entity certificate correctly");

    let names = cert
        .dns_names()
        .expect("we should get a result even without subjectAltNames");

    assert!(names.is_empty());
}
