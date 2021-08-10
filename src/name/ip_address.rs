// Copyright 2015-2020 Brian Smith.
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

use crate::Error;

// https://tools.ietf.org/html/rfc5280#section-4.2.1.10 says:
//
//     For IPv4 addresses, the iPAddress field of GeneralName MUST contain
//     eight (8) octets, encoded in the style of RFC 4632 (CIDR) to represent
//     an address range [RFC4632].  For IPv6 addresses, the iPAddress field
//     MUST contain 32 octets similarly encoded.  For example, a name
//     constraint for "class C" subnet 192.0.2.0 is represented as the
//     octets C0 00 02 00 FF FF FF 00, representing the CIDR notation
//     192.0.2.0/24 (mask 255.255.255.0).
pub(super) fn presented_id_matches_constraint(
    name: untrusted::Input,
    constraint: untrusted::Input,
) -> Result<bool, Error> {
    if name.len() != 4 && name.len() != 16 {
        return Err(Error::BadDER);
    }
    if constraint.len() != 8 && constraint.len() != 32 {
        return Err(Error::BadDER);
    }

    // an IPv4 address never matches an IPv6 constraint, and vice versa.
    if name.len() * 2 != constraint.len() {
        return Ok(false);
    }

    let (constraint_address, constraint_mask) = constraint.read_all(Error::BadDER, |value| {
        let address = value.read_bytes(constraint.len() / 2).unwrap();
        let mask = value.read_bytes(constraint.len() / 2).unwrap();
        Ok((address, mask))
    })?;

    let mut name = untrusted::Reader::new(name);
    let mut constraint_address = untrusted::Reader::new(constraint_address);
    let mut constraint_mask = untrusted::Reader::new(constraint_mask);
    loop {
        let name_byte = name.read_byte().unwrap();
        let constraint_address_byte = constraint_address.read_byte().unwrap();
        let constraint_mask_byte = constraint_mask.read_byte().unwrap();
        if ((name_byte ^ constraint_address_byte) & constraint_mask_byte) != 0 {
            return Ok(false);
        }
        if name.at_end() {
            break;
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRESENTED_MATCHES_CONTRAINT: &[(&str, &str, &str, Result<bool, Error>)] = &[
        // Cannot mix IpV4 with IpV6 and viceversa
        ("2001:db8::", "8.8.8.8", "255.255.255.255", Ok(false)),
        ("8.8.8.8", "2001:db8::", "ffff::", Ok(false)),
        // IpV4
        ("8.8.8.8", "8.8.8.8", "255.255.255.255", Ok(true)),
        ("8.8.8.9", "8.8.8.8", "255.255.255.255", Ok(false)),
        ("8.8.8.9", "8.8.8.8", "255.255.255.254", Ok(true)),
        ("8.8.8.10", "8.8.8.8", "255.255.255.254", Ok(false)),
        ("8.8.8.10", "8.8.8.8", "255.255.255.0", Ok(true)),
        ("8.8.15.10", "8.8.8.8", "255.255.248.0", Ok(true)),
        ("8.8.16.10", "8.8.8.8", "255.255.248.0", Ok(false)),
        ("8.8.16.10", "8.8.8.8", "255.255.0.0", Ok(true)),
        ("8.31.16.10", "8.8.8.8", "255.224.0.0", Ok(true)),
        ("8.32.16.10", "8.8.8.8", "255.224.0.0", Ok(false)),
        ("8.32.16.10", "8.8.8.8", "255.0.0.0", Ok(true)),
        ("63.32.16.10", "8.8.8.8", "192.0.0.0", Ok(true)),
        ("64.32.16.10", "8.8.8.8", "192.0.0.0", Ok(false)),
        ("64.32.16.10", "8.8.8.8", "0.0.0.0", Ok(true)),
        // IpV6
        ("2001:db8::", "2001:db8::", "ffff:ffff::", Ok(true)),
        ("2001:db9::", "2001:db8::", "ffff:ffff::", Ok(false)),
        ("2001:db9::", "2001:db8::", "ffff:fffe::", Ok(true)),
        ("2001:dba::", "2001:db8::", "ffff:fffe::", Ok(false)),
        ("2001:dba::", "2001:db8::", "ffff:ff00::", Ok(true)),
        ("2001:dca::", "2001:db8::", "ffff:fe00::", Ok(true)),
        ("2001:fca::", "2001:db8::", "ffff:fe00::", Ok(false)),
        ("2001:fca::", "2001:db8::", "ffff:0000::", Ok(true)),
        ("2000:fca::", "2001:db8::", "fffe:0000::", Ok(true)),
        ("2003:fca::", "2001:db8::", "fffe:0000::", Ok(false)),
        ("2003:fca::", "2001:db8::", "ff00:0000::", Ok(true)),
        ("1003:fca::", "2001:db8::", "e000:0000::", Ok(false)),
        ("1003:fca::", "2001:db8::", "0000:0000::", Ok(true)),
    ];

    #[cfg(feature = "std")]
    #[test]
    fn presented_matches_constraint_test() {
        use std::boxed::Box;
        use std::net::IpAddr;

        for &(presented, constraint_address, constraint_mask, expected_result) in
            PRESENTED_MATCHES_CONTRAINT
        {
            let presented_bytes: Box<[u8]> = match presented.parse::<IpAddr>().unwrap() {
                IpAddr::V4(p) => Box::new(p.octets()),
                IpAddr::V6(p) => Box::new(p.octets()),
            };
            let ca_bytes: Box<[u8]> = match constraint_address.parse::<IpAddr>().unwrap() {
                IpAddr::V4(ca) => Box::new(ca.octets()),
                IpAddr::V6(ca) => Box::new(ca.octets()),
            };
            let cm_bytes: Box<[u8]> = match constraint_mask.parse::<IpAddr>().unwrap() {
                IpAddr::V4(cm) => Box::new(cm.octets()),
                IpAddr::V6(cm) => Box::new(cm.octets()),
            };
            let constraint_bytes = [ca_bytes, cm_bytes].concat();
            let actual_result = presented_id_matches_constraint(
                untrusted::Input::from(&presented_bytes),
                untrusted::Input::from(&constraint_bytes),
            );
            assert_eq!(
                actual_result, expected_result,
                "presented_id_matches_constraint(\"{:?}\", \"{:?}\")",
                presented_bytes, constraint_bytes
            );
        }
    }
}
