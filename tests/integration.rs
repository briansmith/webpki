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

extern crate untrusted;
extern crate webpki;
extern crate ring;

use untrusted::Input;
use webpki::*;

static ALL_SIGALGS: &'static [&'static SignatureAlgorithm] = &[
    &ECDSA_P256_SHA256,
    &ECDSA_P256_SHA384,
    &ECDSA_P384_SHA256,
    &ECDSA_P384_SHA384,
    &RSA_PKCS1_2048_8192_SHA1,
    &RSA_PKCS1_2048_8192_SHA256,
    &RSA_PKCS1_2048_8192_SHA384,
    &RSA_PKCS1_2048_8192_SHA512,
    &RSA_PKCS1_3072_8192_SHA384
];

/* Checks we can verify netflix's cert chain.  This is notable
 * because they're rooted at a Verisign v1 root. */
#[test]
pub fn netflix()
{
    let ee = include_bytes!("netflix/ee.der");
    let inter = include_bytes!("netflix/inter.der");
    let ca = include_bytes!("netflix/ca.der");

    let ee_input = Input::from(ee);
    let inter_vec = vec![ Input::from(inter) ];
    let anchors = vec![
        trust_anchor_util::cert_der_as_trust_anchor(
            Input::from(ca)
        ).unwrap()
    ];

    let time = Time::from_seconds_from_unix_epoch(1492441716);

    let cert = webpki::EndEntityCert::from(ee_input).unwrap();
    cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors,
                                         &inter_vec, time)
        .unwrap();
}

#[test]
fn read_root_with_zero_serial() {
    let ca = include_bytes!("misc/serial_zero.der");
    trust_anchor_util::cert_der_as_trust_anchor(
        Input::from(ca)
    ).expect("godaddy cert should parse as anchor");
}

#[test]
fn read_root_with_neg_serial() {
    let ca = include_bytes!("misc/serial_neg.der");
    trust_anchor_util::cert_der_as_trust_anchor(
        Input::from(ca)
    ).expect("idcat cert should parse as anchor");
}

#[cfg(feature = "use_std")]
#[test]
fn time_constructor() {
    use std::time;

    Time::from(time::SystemTime::now());
}
