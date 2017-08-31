// Copyright 2014-2017 Brian Smith.

extern crate untrusted;
extern crate webpki;

// (name, is_valid)
static DNS_NAME_VALIDITY: &[(&'static [u8], bool)] = &[
    (b"a", true),
    (b"a.b", true),
    (b"a.b.c", true),
    (b"a.b.c.d", true),

    // Hyphens, one component.
    (b"-", false),
    (b"-a", false),
    (b"a-", false),
    (b"a-b", true),

    // Hyphens, last component.
    (b"a.-", false),
    (b"a.-a", false),
    (b"a.a-", false),
    (b"a.a-b", true),

    // Hyphens, not last component.
    (b"-.a", false),
    (b"-a.a", false),
    (b"a-.a", false),
    (b"a-b.a", true),

    // Underscores, one component.
    (b"_", true), // TODO: Perhaps this should be rejected for '_' being sole character?.
    (b"_a", true), // TODO: Perhaps this should be rejected for '_' being 1st?
    (b"a_", true),
    (b"a_b", true),

    // Underscores, last component.
    (b"a._", true), // TODO: Perhaps this should be rejected for '_' being sole character?.
    (b"a._a", true), // TODO: Perhaps this should be rejected for '_' being 1st?
    (b"a.a_", true),
    (b"a.a_b", true),

    // Underscores, not last component.
    (b"_.a", true), // TODO: Perhaps this should be rejected for '_' being sole character?.
    (b"_a.a", true),
    (b"a_.a", true),
    (b"a_b.a", true),

    // empty labels
    (b"", false),
    (b".", false),
    (b"a", true),
    (b".a", false),
    (b".a.b", false),
    (b"..a", false),
    (b"a..b", false),
    (b"a...b", false),
    (b"a..b.c", false),
    (b"a.b..c", false),
    (b".a.b.c.", false),

    // absolute names
    (b"a.", true),
    (b"a.b.", true),
    (b"a.b.c.", true),

    // absolute names with empty label at end
    (b"a..", false),
    (b"a.b..", false),
    (b"a.b.c..", false),
    (b"a...", false),

    // Punycode
    (b"xn--", false),
    (b"xn--.", false),
    (b"xn--.a", false),
    (b"a.xn--", false),
    (b"a.xn--.", false),
    (b"a.xn--.b", false),
    (b"a.xn--.b", false),
    (b"a.xn--\0.b", false),
    (b"a.xn--a.b", true),
    (b"xn--a", true),
    (b"a.xn--a", true),
    (b"a.xn--a.a", true),
    (b"\xc4\x95.com", false), // UTF-8 ĕ
    (b"xn--jea.com", true), // punycode ĕ
    (b"xn--\xc4\x95.com", false), // UTF-8 ĕ, malformed punycode + UTF-8 mashup

    // Surprising punycode
    (b"xn--google.com", true), // 䕮䕵䕶䕱.com
    (b"xn--citibank.com", true), // 岍岊岊岅岉岎.com
    (b"xn--cnn.com", true), // 䁾.com
    (b"a.xn--cnn", true), // a.䁾
    (b"a.xn--cnn.com", true), // a.䁾.com

    (b"1.2.3.4", false), // IPv4 address
    (b"1::2", false), // IPV6 address

    // whitespace not allowed anywhere.
    (b" ", false),
    (b" a", false),
    (b"a ", false),
    (b"a b", false),
    (b"a.b 1", false),
    (b"a\t", false),

    // Nulls not allowed
    (b"\0", false),
    (b"a\0", false),
    (b"example.org\0.example.com", false), // Hi Moxie!
    (b"\0a", false),
    (b"xn--\0", false),

    // Allowed character set
    (b"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z", true),
    (b"A.B.C.D.E.F.G.H.I.J.K.L.M.N.O.P.Q.R.S.T.U.V.W.X.Y.Z", true),
    (b"0.1.2.3.4.5.6.7.8.9.a", true), // "a" needed to avoid numeric last label
    (b"a-b", true), // hyphen (a label cannot start or end with a hyphen)

    // An invalid character in various positions
    (b"!", false),
    (b"!a", false),
    (b"a!", false),
    (b"a!b", false),
    (b"a.!", false),
    (b"a.a!", false),
    (b"a.!a", false),
    (b"a.a!a", false),
    (b"a.!a.a", false),
    (b"a.a!.a", false),
    (b"a.a!a.a", false),

    // Various other invalid characters
    (b"a!", false),
    (b"a@", false),
    (b"a#", false),
    (b"a$", false),
    (b"a%", false),
    (b"a^", false),
    (b"a&", false),
    (b"a*", false),
    (b"a(", false),
    (b"a)", false),

    // last label can't be fully numeric
    (b"1", false),
    (b"a.1", false),

    // other labels can be fully numeric
    (b"1.a", true),
    (b"1.2.a", true),
    (b"1.2.3.a", true),

    // last label can be *partly* numeric
    (b"1a", true),
    (b"1.1a", true),
    (b"1-1", true),
    (b"a.1-1", true),
    (b"a.1-a", true),

    // labels cannot start with a hyphen
    (b"-", false),
    (b"-1", false),

    // labels cannot end with a hyphen
    (b"1-", false),
    (b"1-.a", false),
    (b"a-", false),
    (b"a-.a", false),
    (b"a.1-.a", false),
    (b"a.a-.a", false),

    // labels can contain a hyphen in the middle
    (b"a-b", true),
    (b"1-2", true),
    (b"a.a-1", true),

    // multiple consecutive hyphens allowed
    (b"a--1", true),
    (b"1---a", true),
    (b"a-----------------b", true),

    // Wildcard specifications are not valid reference names.
    (b"*.a", false),
    (b"a*", false),
    (b"a*.", false),
    (b"a*.a", false),
    (b"a*.a.", false),
    (b"*.a.b", false),
    (b"*.a.b.", false),
    (b"a*.b.c", false),
    (b"*.a.b.c", false),
    (b"a*.b.c.d", false),

    // Multiple wildcards.
    (b"a**.b.c", false),
    (b"a*b*.c.d", false),
    (b"a*.b*.c", false),

    // Wildcards not in the first label.
    (b"a.*", false),
    (b"a.*.b", false),
    (b"a.b.*", false),
    (b"a.b*.c", false),
    (b"*.b*.c", false),
    (b".*.a.b", false),
    (b".a*.b.c", false),

    // Wildcards not at the end of the first label.
    (b"*a.b.c", false),
    (b"a*b.c.d", false),

    // Wildcards and IDNA prefix.
    (b"x*.a.b", false),
    (b"xn*.a.b", false),
    (b"xn-*.a.b", false),
    (b"xn--*.a.b", false),
    (b"xn--w*.a.b", false),

    // Redacted labels from RFC6962bis draft 4
    // https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-04#section-3.2.2
    (b"(PRIVATE).foo", false),

    // maximum label length is 63 characters
    (b"123456789012345678901234567890123456789012345678901234567890abc", true),
    (b"123456789012345678901234567890123456789012345678901234567890abcd", false),

    // maximum total length is 253 characters
    (b"12345678901234567890123456789012345678901234567890.12345678901234567890123456789012345678901234567890.12345678901234567890123456789012345678901234567890.12345678901234567890123456789012345678901234567890.123456789012345678901234567890123456789012345678a",
     true),
    (b"12345678901234567890123456789012345678901234567890.12345678901234567890123456789012345678901234567890.12345678901234567890123456789012345678901234567890.12345678901234567890123456789012345678901234567890.1234567890123456789012345678901234567890123456789a",
     false),
];

#[test]
fn dns_name_ref_try_from_ascii_test() {
    for &(s, is_valid) in DNS_NAME_VALIDITY {
        assert_eq!(
            webpki::DNSNameRef::try_from_ascii(untrusted::Input::from(s))
                .is_ok(),
            is_valid,
            "DNSNameRef::try_from_ascii_str failed for \"{:?}\"", s);
    }
}
