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

use super::{Error, FatalError, PublicKey};
use super::der;
use super::input::*;
use ring;

pub struct SignedData<'a> {
    data: Input<'a>,
    algorithm: Input<'a>,
    signature: Input<'a>,
}

#[allow(non_camel_case_types)]
enum PublicKeyAlgorithm {
    ECDSA,
    RSA_PKCS1,
}

fn signature_algorithm_identifier_value(input: &mut Reader)
        -> Result<(PublicKeyAlgorithm, ring::SignatureDigestAlgorithm),
                  Error> {
    // RFC 5758 Section 3.2 (ECDSA with SHA-2), and RFC 3279 Section 2.2.3
    // (ECDSA with SHA-1) say that parameters must be omitted.
    //
    // RFC 4055 Section 5 and RFC 3279 Section 2.2.1 both say that parameters
    // for RSA must be encoded as NULL; we relax that requirement by allowing
    // the NULL to be omitted, to match all the other signature algorithms we
    // support and for compatibility.

    let algorithm_id = try!(der::expect_tag_and_get_input(input,
                                                          der::Tag::OID));

    // RFC 5758 Section 3.2 (ecdsa-with-SHA224 is intentionally excluded)
    // python DottedOIDToCode.py ecdsa-with-SHA256 1.2.840.10045.4.3.2
    const ECDSA_WITH_SHA256: [u8; 8] = [
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
    ];
    // python DottedOIDToCode.py ecdsa-with-SHA384 1.2.840.10045.4.3.3
    const ECDSA_WITH_SHA384: [u8; 8] = [
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03
    ];
    // python DottedOIDToCode.py ecdsa-with-SHA512 1.2.840.10045.4.3.4
    const ECDSA_WITH_SHA512: [u8; 8] = [
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04
    ];

    // RFC 4055 Section 5 (sha224WithRSAEncryption is intentionally excluded)
    // python DottedOIDToCode.py sha256WithRSAEncryption 1.2.840.113549.1.1.11
    // (name tweaked)
    const SHA256_WITH_RSA_ENCRYPTION: [u8; 9] = [
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
    ];
    // python DottedOIDToCode.py sha384WithRSAEncryption 1.2.840.113549.1.1.12
    // (name tweaked)
    const SHA384_WITH_RSA_ENCRYPTION: [u8; 9] = [
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c
    ];
    // python DottedOIDToCode.py sha512WithRSAEncryption 1.2.840.113549.1.1.13
    // (name tweaked)
    const SHA512_WITH_RSA_ENCRYPTION: [u8; 9] = [
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d
    ];

    // RFC 3279 Section 2.2.1
    // python DottedOIDToCode.py sha-1WithRSAEncryption 1.2.840.113549.1.1.5
    // (name tweaked)
    const SHA1_WITH_RSA_ENCRYPTION: [u8; 9] = [
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05
    ];

    // NIST Open Systems Environment (OSE) Implementor's Workshop (OIW)
    // http://www.oiw.org/agreements/stable/12s-9412.txt (no longer works).
    // http://www.imc.org/ietf-pkix/old-archive-97/msg01166.html
    // We need to support this this non-PKIX OID for compatibility.
    // python DottedOIDToCode.py sha1WithRSASignature 1.3.14.3.2.29 (name
    // tweaked)
    const SHA1_WITH_RSA_SIGNATURE: [u8; 5] = [
      0x2b, 0x0e, 0x03, 0x02, 0x1d
    ];

    // RFC 3279 Section 2.2.3
    // python DottedOIDToCode.py ecdsa-with-SHA1 1.2.840.10045.4.1
    const ECDSA_WITH_SHA1: [u8; 7] = [
      0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01
    ];

    // In order of approximate commonality.
    let (public_key_algorithm, digest_algorithm) =
        if input_equals(algorithm_id, &SHA256_WITH_RSA_ENCRYPTION) {
            try!(der::optional_null(input));
            (PublicKeyAlgorithm::RSA_PKCS1, ring::SignatureDigestAlgorithm::SHA256)
        } else if input_equals(algorithm_id, &ECDSA_WITH_SHA256) {
            (PublicKeyAlgorithm::ECDSA, ring::SignatureDigestAlgorithm::SHA256)
        } else if input_equals(algorithm_id, &SHA1_WITH_RSA_ENCRYPTION) {
            try!(der::optional_null(input));
            (PublicKeyAlgorithm::RSA_PKCS1, ring::SignatureDigestAlgorithm::SHA1)
        } else if input_equals(algorithm_id, &ECDSA_WITH_SHA1) {
            (PublicKeyAlgorithm::ECDSA, ring::SignatureDigestAlgorithm::SHA1)
        } else if input_equals(algorithm_id, &ECDSA_WITH_SHA384) {
            (PublicKeyAlgorithm::ECDSA, ring::SignatureDigestAlgorithm::SHA384)
        } else if input_equals(algorithm_id, &ECDSA_WITH_SHA512) {
            (PublicKeyAlgorithm::ECDSA, ring::SignatureDigestAlgorithm::SHA512)
        } else if input_equals(algorithm_id, &SHA384_WITH_RSA_ENCRYPTION) {
            try!(der::optional_null(input));
            (PublicKeyAlgorithm::RSA_PKCS1, ring::SignatureDigestAlgorithm::SHA384)
        } else if input_equals(algorithm_id, &SHA512_WITH_RSA_ENCRYPTION) {
            try!(der::optional_null(input));
            (PublicKeyAlgorithm::RSA_PKCS1, ring::SignatureDigestAlgorithm::SHA512)
        } else if input_equals(algorithm_id, &SHA1_WITH_RSA_SIGNATURE) {
            try!(der::optional_null(input));
            (PublicKeyAlgorithm::RSA_PKCS1, ring::SignatureDigestAlgorithm::SHA1)
        } else {
            return Err(Error::UnsupportedSignatureAlgorithm);
        };

    Ok((public_key_algorithm, digest_algorithm))
}

// Parses the concatenation of tbs||signatureAlgorithm||signatureValue that is
// common in the X.509 certificate and OCSP response syntaxes.
//
// X.509 Certificates (RFC 5280) look like this:
//
// ```ASN.1
// Certificate (SEQUENCE) {
//     tbsCertificate TBSCertificate,
//     signatureAlgorithm AlgorithmIdentifier,
//     signatureValue BIT STRING
// }
//
// OCSP responses (RFC 6960) look like this:
//
// ```ASN.1
// BasicOCSPResponse {
//     tbsResponseData ResponseData,
//     signatureAlgorithm AlgorithmIdentifier,
//     signature BIT STRING,
//     certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
// }
// ```
//
// Note that this function does NOT parse the outermost `SEQUENCE` or the
// `certs` value.
//
// The return value's first component is the contents of
// `tbsCertificate`/`tbsResponseData`; the second component is a `SignedData`
// structure that can be passed to `verify_signed_data`.
pub fn parse_signed_data<'a>(der: &mut Reader<'a>)
                             -> Result<(Input<'a>, SignedData<'a>), Error> {
    let mark1 = der.mark();
    let tbs = try!(der::expect_tag_and_get_input(der, der::Tag::Sequence));
    let mark2 = der.mark();
    let data = try!(der.get_input_between_marks(mark1, mark2)
                       .ok_or(Error::Fatal(FatalError::ImpossibleState)));
    let algorithm = try!(der::expect_tag_and_get_input(der,
                                                       der::Tag::Sequence));
    let signature = try!(der::bit_string_with_no_unused_bits(der));


    Ok((tbs,
        SignedData {
            data: data,
            algorithm: algorithm,
            signature: signature
        }))
}

/// Parses a SubjectPublicKeyInfo value (without the tag and length).
pub fn parse_spki_value<'a>(input: &mut Reader<'a>)
                            -> Result<PublicKey<'a>, Error> {
    let algorithm =
        try!(der::expect_tag_and_get_input(input, der::Tag::Sequence));
    let subject_public_key =
        try!(der::bit_string_with_no_unused_bits(input));

    read_all(algorithm, Error::BadDER, |algorithm| {
        // RFC 3279 Section 2.3.1
        // python DottedOIDToCode.py rsaEncryption 1.2.840.113549.1.1.1
        // (name tweaked)
        const RSA_ENCRYPTION: [u8; 9] = [
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
        ];

        // RFC 3279 Section 2.3.5 and RFC 5480 Section 2.1.1
        // python DottedOIDToCode.py id-ecPublicKey 1.2.840.10045.2.1
        // (name tweaked)
        const ID_EC_PUBLIC_KEY: [u8; 7] = [
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
        ];

        let algorithm_oid =
            try!(der::expect_tag_and_get_input(algorithm, der::Tag::OID));
        if input_equals(algorithm_oid, &ID_EC_PUBLIC_KEY) {
            make_ec_public_key(algorithm, subject_public_key)
        } else if input_equals(algorithm_oid, &RSA_ENCRYPTION) {
            make_rsa_public_key(algorithm, subject_public_key)
        } else {
            Err(Error::UnsupportedKeyAlgorithm)
        }
    })
}

fn make_ec_public_key<'a>(algorithm: &mut Reader, spk: Input<'a>) ->
                          Result<PublicKey<'a>, Error> {
    // An id-ecPublicKey algorithm_identifier has a parameter that identifies
    // the curve being used. Although RFC 5480 specifies multiple forms, we
    // only supported the NamedCurve form, where the curve is identified by an
    // OID.

    // RFC 5480
    // python DottedOIDToCode.py secp256r1 1.2.840.10045.3.1.7
    const SECP256R1: [u8; 8] = [
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    ];

    // RFC 5480
    // python DottedOIDToCode.py secp384r1 1.3.132.0.34
    const SECP384R1: [u8; 5] = [
        0x2b, 0x81, 0x04, 0x00, 0x22
    ];

    // RFC 5480
    // python DottedOIDToCode.py secp521r1 1.3.132.0.35
    const SECP521R1: [u8; 5] = [
        0x2b, 0x81, 0x04, 0x00, 0x23
    ];

    let named_curve_oid_value =
        try!(der::expect_tag_and_get_input(algorithm, der::Tag::OID));

    let curve: &'static ring::EllipticCurve =
        if input_equals(named_curve_oid_value, &SECP256R1) {
            &ring::CURVE_P256
        } else if input_equals(named_curve_oid_value, &SECP384R1) {
            &ring::CURVE_P384
        } else if input_equals(named_curve_oid_value, &SECP521R1) {
            &ring::CURVE_P521
        } else {
            return Err(Error::UnsupportedEllipticCurve);
        };

    // TODO: Check whether the application wants to allow the curve. For now,
    // we assume all 3 supported curves are acceptable.

    // NOTE: mozilla::pkix parses the subjectPublicKey and checks whether it
    // makes sense syntactically (e.g. that only uncompressed points are
    // accepted). libwebpki instead relies on the crypto library to do that.

    Ok(PublicKey::EC(spk, curve))
}

fn make_rsa_public_key<'a>(algorithm: &mut Reader<'a>, spk: Input<'a>)
                           -> Result<PublicKey<'a>, Error> {
    // RFC 3279 Section 2.3.1 says "The parameters field MUST have ASN.1 type
    // NULL for this algorithm identifier."
    try!(der::null(algorithm));

    // NOTE: mozilla::pkix parses the subjectPublicKey and checks whether it
    // is syntactically valid. It also asks the TrustDomain if the modulus size
    // is acceptable. libwebpki instead relies on the crypto library to do
    // those checks.

    Ok(PublicKey::RSA(spk))
}

// TODO: Replace the use of Vec<u8> with the use of a type that does not use
// the heap.
fn digest_data(digest_alg: ring::SignatureDigestAlgorithm, input: Input)
               -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    let input_as_slice = input.as_slice_less_safe();
    match digest_alg {
        ring::SignatureDigestAlgorithm::SHA256 =>
            result.extend(&ring::digest::<ring::SHA256>(input_as_slice)[..]),
        ring::SignatureDigestAlgorithm::SHA384 =>
            result.extend(&ring::digest::<ring::SHA384>(input_as_slice)[..]),
        ring::SignatureDigestAlgorithm::SHA512 =>
            result.extend(&ring::digest::<ring::SHA512>(input_as_slice)[..]),
        ring::SignatureDigestAlgorithm::SHA1 =>
            result.extend(&ring::digest::<ring::SHA1>(input_as_slice)[..])
    };
    result
}

pub fn verify_signed_data(public_key: &PublicKey, signed_data: &SignedData)
                          -> Result<(), Error> {
    let (public_key_alg, digest_alg) =
        try!(read_all(signed_data.algorithm, Error::BadDER,
                      signature_algorithm_identifier_value));

    // TODO: mozilla::pkix asks the TrustDomain to digest the data and verify
    // the signature, so that the TrustDomain can choose the crypto
    // implementations and also so it can choose which algorithms and
    // parameters are acceptable. We should eventually so similar.

    let digest = digest_data(digest_alg, signed_data.data);

    let verified = match (public_key_alg, public_key) {
        (PublicKeyAlgorithm::ECDSA, &PublicKey::EC(public_point, curve)) =>
            ring::verify_ecdsa_signed_digest_asn1(
                digest_alg, &digest[..],
                signed_data.signature.as_slice_less_safe(), curve,
                public_point.as_slice_less_safe()),
        (PublicKeyAlgorithm::RSA_PKCS1, &PublicKey::RSA(rsa_public_key)) =>
            ring::verify_rsa_pkcs1_signed_digest_asn1(digest_alg, &digest[..],
                signed_data.signature.as_slice_less_safe(),
                rsa_public_key.as_slice_less_safe()),
        _ => Err(()) // The algorithms do not match.
    };

    verified.or(Err(Error::BadSignature))
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use rustc_serialize::base64::FromBase64;
    use std;
    use std::fs;
    use std::io::{BufRead, BufReader, Lines};
    use std::path::PathBuf;
    use super::*;
    use super::super::{der, Error, PublicKey};
    use super::super::input::{Input, read_all};

    // TODO: The expected results need to be modified for SHA-1 deprecation
    // and RSA<2048 deprecation.

    fn parse_spki<'a>(input: &'a [u8]) -> Result<PublicKey<'a>, Error> {
        read_all(Input::new(input).unwrap(), Error::BadDER, |input| {
            der::nested(input, der::Tag::Sequence, parse_spki_value)
        })
    }

    macro_rules! test_parse_spki_bad {
        ($fn_name:ident, $file_name:expr, $error:expr) => {
            #[test]
            fn $fn_name() {
                let tsd = parse_test_signed_data($file_name);
                match parse_spki(&tsd.spki) {
                    Ok(_) => unreachable!(),
                    Err(actual_error) => assert_eq!(actual_error, $error)
                }
            }
        }
    }

    macro_rules! test_verify_signed_data {
        ($fn_name:ident, $file_name:expr, $expected_result:expr) => {
            #[test]
            fn $fn_name() {
                let tsd = parse_test_signed_data($file_name);
                let key = parse_spki(&tsd.spki).unwrap();

                // we can't use `parse_signed_data` because it requires `data`
                // to be an ASN.1 SEQUENCE, and that isn't the case with
                // Chromium's test data. TODO: The test data set should be
                // expanded with SEQUENCE-wrapped data so that we can actually
                // test `parse_signed_data`.

                let algorithm = read_all(Input::new(&tsd.algorithm).unwrap(),
                                         Error::BadDER, |input| {
                    der::expect_tag_and_get_input(input, der::Tag::Sequence)
                }).unwrap();

                let signature = read_all(Input::new(&tsd.signature).unwrap(),
                                         Error::BadDER, |input| {
                    der::bit_string_with_no_unused_bits(input)
                }).unwrap();

                let signed_data = SignedData {
                    data: Input::new(&tsd.data).unwrap(),
                    algorithm: algorithm,
                    signature: signature
                };

                assert_eq!($expected_result,
                           verify_signed_data(&key, &signed_data));
            }
        }
    }

    test_parse_spki_bad!(test_ecdsa_prime256v1_sha512_spki_params_null,
                         "ecdsa-prime256v1-sha512-spki-params-null.pem",
                         Error::BadDER);
    // TODO:
    // test_parse_signed_data_bad!(
    //     test_ecdsa_prime256v1_sha512_unused_bits_signature,
    //     "ecdsa-prime256v1-sha512-unused-bits-signature.pem",
    //     Error::BadDER);
    test_parse_spki_bad!(test_ecdsa_prime256v1_sha512_using_ecdh_key,
                         "ecdsa-prime256v1-sha512-using-ecdh-key.pem",
                         Error::UnsupportedKeyAlgorithm);
    test_parse_spki_bad!(test_ecdsa_prime256v1_sha512_using_ecmqv_key,
                         "ecdsa-prime256v1-sha512-using-ecmqv-key.pem",
                         Error::UnsupportedKeyAlgorithm);
    test_verify_signed_data!(test_ecdsa_prime256v1_sha512_using_rsa_algorithm,
                             "ecdsa-prime256v1-sha512-using-rsa-algorithm.pem",
                             Err(Error::BadSignature));
    test_verify_signed_data!(
        test_ecdsa_prime256v1_sha512_wrong_signature_format,
        "ecdsa-prime256v1-sha512-wrong-signature-format.pem",
        Err(Error::BadSignature));
    test_verify_signed_data!(test_ecdsa_prime256v1_sha512,
                             "ecdsa-prime256v1-sha512.pem", Ok(()));
    test_verify_signed_data!(test_ecdsa_secp384r1_sha256_corrupted_data,
                             "ecdsa-secp384r1-sha256-corrupted-data.pem",
                             Err(Error::BadSignature));
    test_verify_signed_data!(test_ecdsa_secp384r1_sha256,
                             "ecdsa-secp384r1-sha256.pem", Ok(()));
    test_verify_signed_data!(test_ecdsa_using_rsa_key,
                             "ecdsa-using-rsa-key.pem",
                             Err(Error::BadSignature));

    test_parse_spki_bad!(test_rsa_pkcs1_sha1_bad_key_der_length,
                         "rsa-pkcs1-sha1-bad-key-der-length.pem",
                         Error::BadDER);
    test_parse_spki_bad!(test_rsa_pkcs1_sha1_bad_key_der_null,
                         "rsa-pkcs1-sha1-bad-key-der-null.pem",
                         Error::BadDER);
    test_parse_spki_bad!(test_rsa_pkcs1_sha1_key_params_absent,
                         "rsa-pkcs1-sha1-key-params-absent.pem",
                         Error::BadDER);
    test_parse_spki_bad!(test_rsa_pkcs1_sha1_using_pss_key_no_params,
                         "rsa-pkcs1-sha1-using-pss-key-no-params.pem",
                         Error::UnsupportedKeyAlgorithm);
    test_verify_signed_data!(test_rsa_pkcs1_sha1_wrong_algorithm,
                             "rsa-pkcs1-sha1-wrong-algorithm.pem",
                             Err(Error::BadSignature));
    test_verify_signed_data!(test_rsa_pkcs1_sha1,
                             "rsa-pkcs1-sha1.pem", Ok(()));
    test_verify_signed_data!(test_rsa_pkcs1_sha256,
                             "rsa-pkcs1-sha256.pem", Ok(()));
    test_parse_spki_bad!(test_rsa_pkcs1_sha256_key_encoded_ber,
                         "rsa-pkcs1-sha256-key-encoded-ber.pem",
                         Error::BadDER);
    test_parse_spki_bad!(test_rsa_pkcs1_sha256_spki_non_null_params,
                         "rsa-pkcs1-sha256-spki-non-null-params.pem",
                         Error::BadDER);
    test_verify_signed_data!(test_rsa_pkcs1_sha256_using_ecdsa_algorithm,
                             "rsa-pkcs1-sha256-using-ecdsa-algorithm.pem",
                             Err(Error::BadSignature));
    test_parse_spki_bad!(test_rsa_pkcs1_sha256_using_id_ea_rsa,
                         "rsa-pkcs1-sha256-using-id-ea-rsa.pem",
                         Error::UnsupportedKeyAlgorithm);

    // PSS is not supported, so our test results are not the same as Chromium's
    // test results for these cases.
    test_parse_spki_bad!(test_rsa_pss_sha1_salt20_using_pss_key_no_params,
                         "rsa-pss-sha1-salt20-using-pss-key-no-params.pem",
                         Error::UnsupportedKeyAlgorithm);
    test_parse_spki_bad!(
        test_rsa_pss_sha1_salt20_using_pss_key_with_null_params,
        "rsa-pss-sha1-salt20-using-pss-key-with-null-params.pem",
        Error::UnsupportedKeyAlgorithm);
    test_verify_signed_data!(test_rsa_pss_sha1_salt20, "rsa-pss-sha1-salt20.pem",
                             Err(Error::UnsupportedSignatureAlgorithm));
    test_verify_signed_data!(test_rsa_pss_sha1_wrong_salt,
                             "rsa-pss-sha1-wrong-salt.pem",
                             Err(Error::UnsupportedSignatureAlgorithm));
    test_verify_signed_data!(test_rsa_pss_sha256_mgf1_sha512_salt33,
                             "rsa-pss-sha256-mgf1-sha512-salt33.pem",
                             Err(Error::UnsupportedSignatureAlgorithm));
    test_parse_spki_bad!(
        test_rsa_pss_sha256_salt10_using_pss_key_with_params,
        "rsa-pss-sha256-salt10-using-pss-key-with-params.pem",
        Error::UnsupportedKeyAlgorithm);
    test_parse_spki_bad!(
        test_rsa_pss_sha256_salt10_using_pss_key_with_wrong_params,
        "rsa-pss-sha256-salt10-using-pss-key-with-wrong-params.pem",
        Error::UnsupportedKeyAlgorithm);
    test_verify_signed_data!(test_rsa_pss_sha256_salt10,
                             "rsa-pss-sha256-salt10.pem",
                             Err(Error::UnsupportedSignatureAlgorithm));

    test_verify_signed_data!(test_rsa_using_ec_key, "rsa-using-ec-key.pem",
                             Err(Error::BadSignature));
    test_verify_signed_data!(test_rsa2048_pkcs1_sha512,
                             "rsa2048-pkcs1-sha512.pem", Ok(()));

    struct TestSignedData {
        spki: Vec<u8>,
        data: Vec<u8>,
        algorithm: Vec<u8>,
        signature: Vec<u8>
    }

    fn parse_test_signed_data(file_name: &str) -> TestSignedData {
        let path =
            PathBuf::from("third-party/chromium/data/verify_signed_data")
	        .join(file_name);
        let file = fs::File::open(path).unwrap();
        let mut lines = BufReader::new(&file).lines();

        let spki = read_pem_section(&mut lines, "PUBLIC KEY");
        let algorithm = read_pem_section(&mut lines, "ALGORITHM");
        let data = read_pem_section(&mut lines, "DATA");
        let signature = read_pem_section(&mut lines, "SIGNATURE");

        TestSignedData {
            spki: spki,
            data: data,
            algorithm: algorithm,
            signature: signature
        }
    }

    type FileLines<'a> = std::io::Lines<std::io::BufReader<&'a std::fs::File>>;

    fn read_pem_section(lines: & mut FileLines, section_name: &str) -> Vec<u8> {
        // Skip comments and header
        let begin_section = format!("-----BEGIN {}-----", section_name);
        loop {
            let line = lines.next().unwrap().unwrap();
            if line == begin_section {
                break;
            }
        }

        let mut base64 = String::new();

        let end_section = format!("-----END {}-----", section_name);
        loop {
            let line = lines.next().unwrap().unwrap();
            if line == end_section {
                break;
            }
            base64.push_str(&line);
        }

        base64.from_base64().unwrap()
    }
}
