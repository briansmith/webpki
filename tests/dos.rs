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

// XXX: rcgen can only build on archs that *ring* 0.16 supports.
#![cfg(all(
    not(all(target_arch = "aarch64", target_os = "windows")),
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "wasm32",
        target_arch = "x86",
        target_arch = "x86_64"
    )
))]
#![cfg(feature = "alloc")]
#![no_std]

extern crate alloc;
use alloc::vec;

use webpki::{
    EndEntityCert, ErrorExt, Time, TlsServerTrustAnchors, TrustAnchor, ECDSA_P256_SHA256,
};

mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use core::convert::TryFrom;

    use super::*;

    enum ChainTrustAnchor {
        InChain,
        NotInChain,
    }

    fn build_degenerate_chain(
        intermediate_count: usize,
        trust_anchor: ChainTrustAnchor,
    ) -> ErrorExt {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;

        let make_issuer = |org_name| {
            let mut ca_params = rcgen::CertificateParams::new(Vec::new());
            ca_params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, org_name);
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            ca_params.alg = alg;
            rcgen::Certificate::from_params(ca_params).unwrap()
        };

        let ca_cert = make_issuer("Bogus Subject");
        let ca_cert_der = ca_cert.serialize_der().unwrap();

        let mut intermediates = Vec::with_capacity(intermediate_count);
        if let ChainTrustAnchor::InChain = trust_anchor {
            intermediates.push(ca_cert_der.to_vec());
        }

        let mut issuer = ca_cert;
        for _ in 0..intermediate_count {
            let intermediate = make_issuer("Bogus Subject");
            let intermediate_der = intermediate.serialize_der_with_signer(&issuer).unwrap();
            intermediates.push(intermediate_der);
            issuer = intermediate;
        }

        let mut ee_params = rcgen::CertificateParams::new(vec!["example.com".to_string()]);
        ee_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        ee_params.alg = alg;
        let ee_cert = rcgen::Certificate::from_params(ee_params).unwrap();
        let ee_cert_der = ee_cert.serialize_der_with_signer(&issuer).unwrap();

        let trust_anchor = match trust_anchor {
            ChainTrustAnchor::InChain => make_issuer("Bogus Trust Anchor").serialize_der().unwrap(),
            ChainTrustAnchor::NotInChain => ca_cert_der.clone(),
        };

        let anchors = &[TrustAnchor::try_from_cert_der(&trust_anchor).unwrap()];
        let time = Time::from_seconds_since_unix_epoch(0x1fed_f00d);
        let cert = EndEntityCert::try_from(&ee_cert_der[..]).unwrap();
        let intermediate_certs = intermediates.iter().map(|x| x.as_ref()).collect::<Vec<_>>();

        cert.verify_is_valid_tls_server_cert_ext(
            &[&ECDSA_P256_SHA256],
            &TlsServerTrustAnchors(anchors),
            &intermediate_certs,
            time,
        )
        .unwrap_err()
    }

    #[test]
    fn test_too_many_signatures() {
        assert!(matches!(
            build_degenerate_chain(5, ChainTrustAnchor::NotInChain),
            ErrorExt::MaximumSignatureChecksExceeded
        ));
    }

    #[test]
    fn test_too_many_path_calls() {
        let result = build_degenerate_chain(10, ChainTrustAnchor::InChain);
        assert!(matches!(result, ErrorExt::MaximumPathBuildCallsExceeded));
    }
}
