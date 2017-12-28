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

#![deny(
    box_pointers,
)]

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
    warnings,
)]

#[cfg(feature = "trust_anchor_util")]
extern crate untrusted;

#[cfg(any(feature = "std", feature = "trust_anchor_util"))]
extern crate webpki;

#[cfg(feature = "trust_anchor_util")]
static ALL_SIGALGS: &'static [&'static webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA1,
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
pub fn netflix()
{
    let ee = include_bytes!("netflix/ee.der");
    let inter = include_bytes!("netflix/inter.der");
    let ca = include_bytes!("netflix/ca.der");

    let ee_input = untrusted::Input::from(ee);
    let inter_vec = vec![ untrusted::Input::from(inter) ];
    let anchors = vec![
        webpki::trust_anchor_util::cert_der_as_trust_anchor(
            untrusted::Input::from(ca)
        ).unwrap()
    ];
    let anchors = webpki::TLSServerTrustAnchors(&anchors);

    let time = webpki::Time::from_seconds_since_unix_epoch(1492441716);

    let cert = webpki::EndEntityCert::from(ee_input).unwrap();
    let _ = cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors,
                                                 &inter_vec, time)
        .unwrap();
}

#[cfg(feature = "trust_anchor_util")]
#[test]
pub fn ed25519()
{
    let ee = include_bytes!("ed25519/ee.der");
    let ca = include_bytes!("ed25519/ca.der");

    let ee_input = untrusted::Input::from(ee);
    let anchors = vec![
        webpki::trust_anchor_util::cert_der_as_trust_anchor(
            untrusted::Input::from(ca)
        ).unwrap()
    ];
    let anchors = webpki::TLSServerTrustAnchors(&anchors);

    let time = webpki::Time::from_seconds_since_unix_epoch(1547363522);

    let cert = webpki::EndEntityCert::from(ee_input).unwrap();
    let _ = cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors,
                                                 &[], time)
        .unwrap();
}

#[cfg(feature = "trust_anchor_util")]
#[test]
fn read_root_with_zero_serial() {
    let ca = include_bytes!("misc/serial_zero.der");
    let _ = webpki::trust_anchor_util::cert_der_as_trust_anchor(
        untrusted::Input::from(ca)
    ).expect("godaddy cert should parse as anchor");
}

#[cfg(feature = "trust_anchor_util")]
#[test]
fn read_root_with_neg_serial() {
    let ca = include_bytes!("misc/serial_neg.der");
    let _ = webpki::trust_anchor_util::cert_der_as_trust_anchor(
        untrusted::Input::from(ca)
    ).expect("idcat cert should parse as anchor");
}

#[cfg(feature = "std")]
#[test]
fn time_constructor() {
    use std;

    let _ = webpki::Time::try_from(std::time::SystemTime::now()).unwrap();
}

#[cfg(feature = "std")]
#[test]
pub fn list_netflix_names()
{
    let ee = include_bytes!("netflix/ee.der");

    expect_cert_dns_names(ee, &[
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
    ]);
}

#[cfg(feature = "std")]
#[test]
pub fn invalid_subject_alt_names()
{
    // same as netflix ee certificate, but with the last name in the list
    // changed to 'www.netflix:com'
    let data = include_bytes!("misc/invalid_subject_alternative_name.der");

    expect_cert_dns_names(data, &[
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
    ]);
}

#[cfg(feature = "std")]
#[test]
pub fn wildcard_subject_alternative_names()
{
    // same as netflix ee certificate, but with the last name in the list
    // changed to 'ww*.netflix:com'
    let data = include_bytes!("misc/dns_names_and_wildcards.der");

    expect_cert_dns_names(data, &[
        "account.netflix.com",
        // NOT "c*.netflix.com",
        "netflix.ca",
        "netflix.com",
        "signup.netflix.com",
        "www.netflix.ca",
        "www1.netflix.com",
        "www2.netflix.com",
        "www3.netflix.com",
        "develop-stage.netflix.com",
        "release-stage.netflix.com",
        "www.netflix.com"
    ]);
}

#[cfg(feature = "std")]
fn expect_cert_dns_names(data: &[u8], expected_names: &[&str])
{
    use std::iter::FromIterator;

    let input = untrusted::Input::from(data);
    let cert = webpki::EndEntityCert::from(input)
      .expect("should parse end entity certificate correctly");

    let expected_names =
        std::collections::HashSet::from_iter(expected_names.iter().cloned());

    let mut actual_names = cert.dns_names()
      .expect("should get all DNS names correctly for end entity cert");

    // Ensure that converting the list to a set doesn't throw away
    // any duplicates that aren't supposed to be there
    assert_eq!(actual_names.len(), expected_names.len());

    let actual_names: std::collections::HashSet<&str> = actual_names.drain(..).map(|name| {
        name.into()
    }).collect();

    assert_eq!(actual_names, expected_names);
}

#[cfg(feature = "std")]
#[test]
pub fn no_subject_alt_names()
{
    let data = include_bytes!("misc/no_subject_alternative_name.der");

    let input = untrusted::Input::from(data);
    let cert = webpki::EndEntityCert::from(input)
      .expect("should parse end entity certificate correctly");

    let names = cert.dns_names().expect("we should get a result even without subjectAltNames");

    assert!(names.is_empty());
}
