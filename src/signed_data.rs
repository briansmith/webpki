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

use ring::signature;
use super::{Error, FatalError};
use super::der;
use untrusted;

pub struct SignedData<'a> {
    data: untrusted::Input<'a>,
    pub algorithm: untrusted::Input<'a>,
    signature: untrusted::Input<'a>,
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
pub fn parse_signed_data<'a>(der: &mut untrusted::Reader<'a>)
                             -> Result<(untrusted::Input<'a>, SignedData<'a>),
                                       Error> {
    let mark1 = der.mark();
    let tbs = try!(der::expect_tag_and_get_input(der, der::Tag::Sequence));
    let mark2 = der.mark();
    let data = try!(der.get_input_between_marks(mark1, mark2)
                       .map_err(|_| Error::Fatal(FatalError::ImpossibleState)));
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

/// Verify `signed_data` using the public key in the DER-encoded
/// SubjectPublicKeyInfo `spki` using one of the algorithms in
/// `supported_algorithms`.
///
/// The algorithm is chosen based on the algorithm information encoded in the
/// algorithm identifiers in `public_key` and `signed_data.algorithm`. The
/// ordering of the algorithms in `supported_algorithms` does not really matter,
/// but generally more common algorithms should go first, as it is scanned
/// linearly for matches.
pub fn verify_signed_data(supported_algorithms: &[&SignatureAlgorithm],
                          spki_value: untrusted::Input,
                          signed_data: &SignedData) -> Result<(), Error> {
    // We need to verify the signature in `signed_data` using the public key
    // in `public_key`. In order to know which *ring* signature verification
    // algorithm to use, we need to know the public key algorithm (ECDSA,
    // RSA PKCS#1, etc.), the curve (if applicable), and the digest algorithm.
    // `signed_data` identifies only the public key algorithm and the digest
    // algorithm, and `public_key` identifies only the public key algorithm and
    // the curve (if any). Thus, we have to combine information from both
    // inputs to figure out which `ring::signature::VerificationAlgorithm` to
    // use to verify the signature.
    //
    // This is all further complicated by the fact that we don't have any
    // implicit knowledge about any algorithms or identifiers, since all of
    // that information is encoded in `supported_algorithms.` In particular, we
    // avoid hard-coding any of that information so that (link-time) dead code
    // elimination will work effectively in eliminating code for unused
    // algorithms.

    // Parse the signature.
    //
    let (algorithm_id, parameters) =
            try!(signed_data.algorithm.read_all(Error::BadDER, |input| {
        let algorithm_id = try!(der::expect_tag_and_get_input(input,
                                                              der::Tag::OID));
        Ok((algorithm_id, input.skip_to_end()))
    }));

    let mut found_signature_alg_match = false;
    //let mut found_key_alg_match = false;
    for supported_alg in supported_algorithms {
        if !supported_alg.signature_alg_oids.into_iter()
                                            .any(|oid| algorithm_id == *oid) {
            continue;
        }

        if !supported_alg.public_key_alg.shared
                         .allowed_signature_alg_parameters
                         .into_iter().any(|allowed| parameters == *allowed) {
            continue;
        }

        found_signature_alg_match = true;

        let (spki_algorithm_oid, spki_curve_oid, spki_key) =
            try!(parse_spki_value(spki_value));
        if spki_algorithm_oid !=
                supported_alg.public_key_alg.shared.spki_algorithm_oid {
            continue;
        }

        match (spki_curve_oid, supported_alg.public_key_alg.curve_oid) {
            (None, None) => (),
            (Some(spki_oid), Some(supported_oid))
                    if spki_oid == supported_oid => (),
            _ => { continue },
        };

        return signature::verify(supported_alg.verification_alg, spki_key,
                                 signed_data.data, signed_data.signature)
                    .map_err(|_| Error::BadSignature);
    }

    if found_signature_alg_match {
        Err(Error::UnsupportedKeyAlgorithmForSignature)
    } else {
        Err(Error::UnsupportedSignatureAlgorithm)
    }
}

// Parse the public key into an algorithm OID, an optional curve OID, and the
// key value. The caller needs to check whether these match the
// `PublicKeyAlgorithm` for the `SignatureAlgorithm` that is matched when
// parsing the signature.
fn parse_spki_value<'a>(input: untrusted::Input<'a>) ->
                        Result<(untrusted::Input<'a>,
                                Option<untrusted::Input<'a>>,
                                untrusted::Input<'a>),
                               Error> {
    input.read_all(Error::BadDER, |input| {
        let (algorithm_oid, curve_oid) =
                try!(der::nested(input, der::Tag::Sequence, Error::BadDER,
                                 |input| {
            let algorithm_oid =
                try!(der::expect_tag_and_get_input(input, der::Tag::OID));

            // We only support algorithm identifiers that have either an
            // OID parameter (id-ecPublicKey using the named curve form as
            // specified in RFC 5480) or a NULL parameter (RSA as specified
            // in RFC 3279 Section 2.3.1).
            let curve_oid = if input.peek(der::Tag::OID as u8) {
                let curve_oid =
                    try!(der::expect_tag_and_get_input(input, der::Tag::OID));
                Some(curve_oid)
            } else {
                try!(der::null(input));
                None
            };
            Ok((algorithm_oid, curve_oid))
        }));
        let public_key = try!(der::bit_string_with_no_unused_bits(input));
        Ok((algorithm_oid, curve_oid, public_key))
    })
}


/// A signature algorithm.
pub struct SignatureAlgorithm {
    signature_alg_oids: &'static [&'static [u8]],
    public_key_alg: &'static PublicKeyAlgorithm,
    verification_alg: &'static signature::VerificationAlgorithm,
}

// RFC 5758 Section 3.2 (ECDSA with SHA-2), and RFC 3279 Section 2.2.3 (ECDSA
// with SHA-1) say that parameters must be omitted. RFC 4055 Section 5 and RFC
// 3279 Section 2.2.1 both say that parameters for RSA must be encoded as NULL;
// we relax that requirement by allowing the NULL to be omitted, to match all
// the other signature algorithms we support and for compatibility.

pub static ECDSA_P256_SHA1: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[ECDSA_SHA1_OID],
    public_key_alg: &ECDSA_P256,
    verification_alg: &signature::ECDSA_P256_SHA1_VERIFY,
};

pub static ECDSA_P256_SHA256: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[ECDSA_SHA256_OID],
    public_key_alg: &ECDSA_P256,
    verification_alg: &signature::ECDSA_P256_SHA256_VERIFY,
};

pub static ECDSA_P256_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[ECDSA_SHA384_OID],
    public_key_alg: &ECDSA_P256,
    verification_alg: &signature::ECDSA_P256_SHA384_VERIFY,
};

pub static ECDSA_P256_SHA512: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[ECDSA_SHA512_OID],
    public_key_alg: &ECDSA_P256,
    verification_alg: &signature::ECDSA_P256_SHA512_VERIFY,
};

pub static ECDSA_P384_SHA1: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[ECDSA_SHA1_OID],
    public_key_alg: &ECDSA_P384,
    verification_alg: &signature::ECDSA_P384_SHA1_VERIFY,
};

pub static ECDSA_P384_SHA256: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[ECDSA_SHA256_OID],
    public_key_alg: &ECDSA_P384,
    verification_alg: &signature::ECDSA_P384_SHA256_VERIFY,
};

pub static ECDSA_P384_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[ECDSA_SHA384_OID],
    public_key_alg: &ECDSA_P384,
    verification_alg: &signature::ECDSA_P384_SHA384_VERIFY,
};

pub static ECDSA_P384_SHA512: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[ECDSA_SHA512_OID],
    public_key_alg: &ECDSA_P384,
    verification_alg: &signature::ECDSA_P384_SHA512_VERIFY,
};


pub static RSA_PKCS1_2048_8192_SHA1: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[RSA_PKCS1_SHA1_OID, RSA_PKCS1_SHA1_OSE_OID],
    public_key_alg: &RSA_PKCS1,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA1_VERIFY,
};

pub static RSA_PKCS1_2048_8192_SHA256: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[RSA_PKCS1_SHA256_OID],
    public_key_alg: &RSA_PKCS1,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256_VERIFY,
};

pub static RSA_PKCS1_2048_8192_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[RSA_PKCS1_SHA384_OID],
    public_key_alg: &RSA_PKCS1,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384_VERIFY,
};

pub static RSA_PKCS1_2048_8192_SHA512: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[RSA_PKCS1_SHA512_OID],
    public_key_alg: &RSA_PKCS1,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA512_VERIFY,
};

pub static RSA_PKCS1_3072_8192_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    signature_alg_oids: &[RSA_PKCS1_SHA384_OID],
    public_key_alg: &RSA_PKCS1,
    verification_alg: &signature::RSA_PKCS1_3072_8192_SHA384_VERIFY,
};


struct PublicKeyAlgorithm {
    shared: &'static PublicKeyAlgorithmSharedInfo,
    curve_oid: Option<&'static [u8]>,
}

static ECDSA_P256: PublicKeyAlgorithm = PublicKeyAlgorithm {
    shared: &ECDSA_SHARED,
    curve_oid: Some(&oid_1_2_840_10045![3, 1, 7]),
};

static ECDSA_P384: PublicKeyAlgorithm = PublicKeyAlgorithm {
    shared: &ECDSA_SHARED,
    curve_oid: Some(&oid_1_3_132![0, 34]),
};

// RFC 3279 Section 2.3.1 says "The parameters field MUST have ASN.1 type
// NULL for this algorithm identifier."
static RSA_PKCS1: PublicKeyAlgorithm = PublicKeyAlgorithm {
    shared: &RSA_PKCS1_SHARED,
    curve_oid: None,
};


struct PublicKeyAlgorithmSharedInfo {
    spki_algorithm_oid: &'static [u8],

    /// XXX: Technically, this should be a property of the `SignatureAlgorithm`,
    /// but it is a property of the `PublicKeyAlgorithm` as an optimization,
    /// as its value never differs for `SignatureAlgorithm`s that have the same
    /// `PublicKeyAlgorithm`. However, keep in mind that this applies to the
    /// `AlgorithmIdentifier` for the *signature*, not the `AlgorithmIdentifier`
    /// for the `SubjectPublicKeyAlgorithm`.
    allowed_signature_alg_parameters: &'static [&'static [u8]],
}

// id-ecPublicKey from RFC 3279 Section 2.3.5 & RFC 5480 Section 2.1.1
const ECDSA_SHARED: PublicKeyAlgorithmSharedInfo = PublicKeyAlgorithmSharedInfo {
    spki_algorithm_oid: &oid_1_2_840_10045![2, 1],

    // RFC 5758 Section 3.2 (ECDSA with SHA-2), and RFC 3279 Section 2.2.3
    // (ECDSA with SHA-1) say that parameters must be omitted in signatures.
    allowed_signature_alg_parameters: &[&[]],
};

const RSA_PKCS1_SHARED: PublicKeyAlgorithmSharedInfo =
        PublicKeyAlgorithmSharedInfo {
    spki_algorithm_oid: &oid_1_2_840_113549![1, 1, 1],

    // RFC 4055 Section 5 and RFC 3279 Section 2.2.1 both say that parameters
    // for RSA PKCS#1 must be encoded as NULL; we relax that requirement by
    // allowing the NULL to be omitted, to match all the other signature
    // algorithms we support and for compatibility.
    allowed_signature_alg_parameters: &[&[], &[0x05, 0x00]], // Optional NULL.
};

// TODO: add documentation for all this stuff.

const ECDSA_SHA1_OID: &'static [u8] = &oid_1_2_840_10045![4, 1, 1];
const ECDSA_SHA256_OID: &'static [u8] = &oid_1_2_840_10045![4, 3, 2];
const ECDSA_SHA384_OID: &'static [u8] = &oid_1_2_840_10045![4, 3, 3];
const ECDSA_SHA512_OID: &'static [u8] = &oid_1_2_840_10045![4, 3, 4];

const RSA_PKCS1_SHA1_OID: &'static [u8] = &oid_1_2_840_113549![1, 1, 5];
const RSA_PKCS1_SHA256_OID: &'static [u8] = &oid_1_2_840_113549![1, 1, 11];
const RSA_PKCS1_SHA384_OID: &'static [u8] = &oid_1_2_840_113549![1, 1, 12];
const RSA_PKCS1_SHA512_OID: &'static [u8] = &oid_1_2_840_113549![1, 1, 13];

// NIST Open Systems Environment (OSE) Implementor's Workshop (OIW)
// http://www.oiw.org/agreements/stable/12s-9412.txt (no longer works).
// http://www.imc.org/ietf-pkix/old-archive-97/msg01166.html
// We need to support this non-PKIX OID for compatibility.
const RSA_PKCS1_SHA1_OSE_OID: &'static [u8] = &oid!(1, 3, 14, 3, 2, 29);


#[cfg(test)]
mod tests {
    use rustc_serialize::base64::FromBase64;
    use std;
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::path::PathBuf;
    use super::super::{der, Error, signed_data};
    use untrusted;

    // TODO: The expected results need to be modified for SHA-1 deprecation.

    macro_rules! test_verify_signed_data {
        ($fn_name:ident, $file_name:expr, $expected_result:expr) => {
            #[test]
            fn $fn_name() {
                test_verify_signed_data($file_name, $expected_result);
            }
        }
    }

    fn test_verify_signed_data(file_name: &str,
                               expected_result: Result<(), Error>) {
        let tsd = parse_test_signed_data(file_name);
        let spki_value = untrusted::Input::new(&tsd.spki).unwrap();
        let spki_value = spki_value.read_all(Error::BadDER, |input| {
            der::expect_tag_and_get_input(input, der::Tag::Sequence)
        }).unwrap();

        // we can't use `parse_signed_data` because it requires `data`
        // to be an ASN.1 SEQUENCE, and that isn't the case with
        // Chromium's test data. TODO: The test data set should be
        // expanded with SEQUENCE-wrapped data so that we can actually
        // test `parse_signed_data`.

        let algorithm = untrusted::Input::new(&tsd.algorithm).unwrap();
        let algorithm = algorithm.read_all(Error::BadDER, |input| {
            der::expect_tag_and_get_input(input, der::Tag::Sequence)
        }).unwrap();

        let signature = untrusted::Input::new(&tsd.signature).unwrap();
        let signature = signature.read_all(Error::BadDER, |input| {
            der::bit_string_with_no_unused_bits(input)
        }).unwrap();

        let signed_data = signed_data::SignedData {
            data: untrusted::Input::new(&tsd.data).unwrap(),
            algorithm: algorithm,
            signature: signature
        };

        assert_eq!(expected_result,
                   signed_data::verify_signed_data(
                        &SUPPORTED_ALGORITHMS_IN_TESTS, spki_value,
                        &signed_data));
    }

    // XXX: This is testing code that isn't even in this module.
    macro_rules! test_verify_signed_data_signature_outer {
        ($fn_name:ident, $file_name:expr, $expected_result:expr) => {
            #[test]
            fn $fn_name() {
                test_verify_signed_data_signature_outer($file_name,
                                                        $expected_result);
            }
        }
    }

    fn test_verify_signed_data_signature_outer(file_name: &str,
                                               expected_error: Error) {
        let tsd = parse_test_signed_data(file_name);
        let signature = untrusted::Input::new(&tsd.signature).unwrap();
        assert_eq!(Err(expected_error),
                   signature.read_all(Error::BadDER, |input| {
            der::bit_string_with_no_unused_bits(input)
        }));
    }

    macro_rules! test_parse_spki_bad {
        ($fn_name:ident, $file_name:expr, $error:expr) => {
            #[test]
            fn $fn_name() {
                test_parse_spki_bad($file_name, $error)
            }
        }
    }

    fn test_parse_spki_bad(file_name: &str, expected_error: Error) {
        let tsd = parse_test_signed_data(file_name);
        let spki_value = untrusted::Input::new(&tsd.spki).unwrap();
        let spki_value = spki_value.read_all(Error::BadDER, |input| {
            der::expect_tag_and_get_input(input, der::Tag::Sequence)
        }).unwrap();
        match signed_data::parse_spki_value(spki_value) {
            Ok(_) => unreachable!(),
            Err(actual_error) => assert_eq!(expected_error, actual_error)
        }
    }

    // XXX: This is testing code that is not even in this module.
    macro_rules! test_parse_spki_bad_outer {
        ($fn_name:ident, $file_name:expr, $error:expr) => {
            #[test]
            fn $fn_name() {
                test_parse_spki_bad_outer($file_name, $error)
            }
        }
    }

    fn test_parse_spki_bad_outer(file_name: &str, expected_error: Error) {
        let tsd = parse_test_signed_data(file_name);
        let spki = untrusted::Input::new(&tsd.spki).unwrap();
        assert_eq!(Err(expected_error),
                   spki.read_all(Error::BadDER, |input| {
            der::expect_tag_and_get_input(input, der::Tag::Sequence)
        }));
    }

    // XXX: Some of the BadDER tests should have better error codes, maybe?

    test_verify_signed_data!(test_ecdsa_prime256v1_sha512_spki_params_null,
                             "ecdsa-prime256v1-sha512-spki-params-null.pem",
                             Err(Error::UnsupportedKeyAlgorithmForSignature));
    test_verify_signed_data_signature_outer!(
        test_ecdsa_prime256v1_sha512_unused_bits_signature,
        "ecdsa-prime256v1-sha512-unused-bits-signature.pem",
        Error::BadDER);
    test_verify_signed_data!(test_ecdsa_prime256v1_sha512_using_ecdh_key,
                             "ecdsa-prime256v1-sha512-using-ecdh-key.pem",
                             Err(Error::UnsupportedKeyAlgorithmForSignature));
    test_verify_signed_data!(test_ecdsa_prime256v1_sha512_using_ecmqv_key,
                             "ecdsa-prime256v1-sha512-using-ecmqv-key.pem",
                             Err(Error::UnsupportedKeyAlgorithmForSignature));
    test_verify_signed_data!(test_ecdsa_prime256v1_sha512_using_rsa_algorithm,
                             "ecdsa-prime256v1-sha512-using-rsa-algorithm.pem",
                             Err(Error::UnsupportedKeyAlgorithmForSignature));
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
                             Err(Error::UnsupportedKeyAlgorithmForSignature));

    test_parse_spki_bad_outer!(test_rsa_pkcs1_sha1_bad_key_der_length,
                               "rsa-pkcs1-sha1-bad-key-der-length.pem",
                               Error::BadDER);
    test_parse_spki_bad_outer!(test_rsa_pkcs1_sha1_bad_key_der_null,
                               "rsa-pkcs1-sha1-bad-key-der-null.pem",
                               Error::BadDER);
    test_verify_signed_data!(test_rsa_pkcs1_sha1_key_params_absent,
                             "rsa-pkcs1-sha1-key-params-absent.pem",
                             Err(Error::BadDER));
    test_parse_spki_bad!(test_rsa_pkcs1_sha1_using_pss_key_no_params,
                         "rsa-pkcs1-sha1-using-pss-key-no-params.pem",
                         Error::BadDER);
    test_verify_signed_data!(test_rsa_pkcs1_sha1_wrong_algorithm,
                             "rsa-pkcs1-sha1-wrong-algorithm.pem",
                             Err(Error::BadSignature));
    // XXX: RSA PKCS#1 with SHA-1 is a supported algorithm, but we only accept
    // 2048-8192 bit keys, and this test file is using a 1024 bit key. Thus,
    // our results differ from Chromium's. TODO: this means we need a 2048+ bit
    // version of this test.
    test_verify_signed_data!(test_rsa_pkcs1_sha1, "rsa-pkcs1-sha1.pem",
                             Err(Error::BadSignature));
    // XXX: RSA PKCS#1 with SHA-1 is a supported algorithm, but we only accept
    // 2048-8192 bit keys, and this test file is using a 1024 bit key. Thus,
    // our results differ from Chromium's. TODO: this means we need a 2048+ bit
    // version of this test.
    test_verify_signed_data!(test_rsa_pkcs1_sha256, "rsa-pkcs1-sha256.pem",
                             Err(Error::BadSignature));
    test_parse_spki_bad_outer!(test_rsa_pkcs1_sha256_key_encoded_ber,
                               "rsa-pkcs1-sha256-key-encoded-ber.pem",
                               Error::BadDER);
    test_parse_spki_bad!(test_rsa_pkcs1_sha256_spki_non_null_params,
                         "rsa-pkcs1-sha256-spki-non-null-params.pem",
                         Error::BadDER);
    test_verify_signed_data!(test_rsa_pkcs1_sha256_using_ecdsa_algorithm,
                             "rsa-pkcs1-sha256-using-ecdsa-algorithm.pem",
                             Err(Error::UnsupportedKeyAlgorithmForSignature));
    test_verify_signed_data!(test_rsa_pkcs1_sha256_using_id_ea_rsa,
                             "rsa-pkcs1-sha256-using-id-ea-rsa.pem",
                             Err(Error::UnsupportedKeyAlgorithmForSignature));

    // XXX: PSS is not supported, so our test results are not the same as
    // Chromium's test results for these cases.
    test_parse_spki_bad!(test_rsa_pss_sha1_salt20_using_pss_key_no_params,
                         "rsa-pss-sha1-salt20-using-pss-key-no-params.pem",
                         Error::BadDER);
    test_verify_signed_data!(
        test_rsa_pss_sha1_salt20_using_pss_key_with_null_params,
        "rsa-pss-sha1-salt20-using-pss-key-with-null-params.pem",
        Err(Error::UnsupportedSignatureAlgorithm));
    test_verify_signed_data!(test_rsa_pss_sha1_salt20, "rsa-pss-sha1-salt20.pem",
                             Err(Error::UnsupportedSignatureAlgorithm));
    test_verify_signed_data!(test_rsa_pss_sha1_wrong_salt,
                             "rsa-pss-sha1-wrong-salt.pem",
                             Err(Error::UnsupportedSignatureAlgorithm));
    test_verify_signed_data!(test_rsa_pss_sha256_mgf1_sha512_salt33,
                             "rsa-pss-sha256-mgf1-sha512-salt33.pem",
                             Err(Error::UnsupportedSignatureAlgorithm));
    test_verify_signed_data!(
        test_rsa_pss_sha256_salt10_using_pss_key_with_params,
        "rsa-pss-sha256-salt10-using-pss-key-with-params.pem",
        Err(Error::UnsupportedSignatureAlgorithm));
    test_verify_signed_data!(
        test_rsa_pss_sha256_salt10_using_pss_key_with_wrong_params,
        "rsa-pss-sha256-salt10-using-pss-key-with-wrong-params.pem",
        Err(Error::UnsupportedSignatureAlgorithm));
    test_verify_signed_data!(test_rsa_pss_sha256_salt10,
                             "rsa-pss-sha256-salt10.pem",
                             Err(Error::UnsupportedSignatureAlgorithm));

    test_verify_signed_data!(test_rsa_using_ec_key, "rsa-using-ec-key.pem",
                             Err(Error::UnsupportedKeyAlgorithmForSignature));
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

    static SUPPORTED_ALGORITHMS_IN_TESTS:
            [&'static signed_data::SignatureAlgorithm; 13] = [
        // Reasonable algorithms.
        &signed_data::RSA_PKCS1_2048_8192_SHA256,
        &signed_data::ECDSA_P256_SHA256,
        &signed_data::ECDSA_P384_SHA384,
        &signed_data::RSA_PKCS1_2048_8192_SHA384,
        &signed_data::RSA_PKCS1_2048_8192_SHA512,
        &signed_data::RSA_PKCS1_3072_8192_SHA384,

        // Algorithms deprecated because they are annoying (P-521) or because
        // they are nonsensical combinations.
        &signed_data::ECDSA_P256_SHA384, // Truncates digest.
        &signed_data::ECDSA_P256_SHA512, // Truncates digest.
        &signed_data::ECDSA_P384_SHA256, // Digest is unnecessarily short.
        &signed_data::ECDSA_P384_SHA512, // Truncates digest.

        // Algorithms deprecated because they are bad.
        &signed_data::RSA_PKCS1_2048_8192_SHA1, // SHA-1
        &signed_data::ECDSA_P256_SHA1, // SHA-1
        &signed_data::ECDSA_P384_SHA1, // SHA-1
    ];
}
