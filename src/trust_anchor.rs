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
