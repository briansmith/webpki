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

use crate::DnsNameRef;

use super::ip_address::{self, IpAddressRef};

/// A DNS name or IP address, which borrows its text representation.
#[derive(Debug, Clone, Copy)]
pub enum DnsNameOrIpRef<'a> {
    /// A valid DNS name
    DnsName(DnsNameRef<'a>),

    /// A valid IP address
    IpAddress(IpAddressRef<'a>),
}

/// An error indicating that a `DnsNameOrIpRef` could not built because the input
/// is not a syntactically-valid DNS Name or IP address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDnsNameOrIpError;

impl<'a> DnsNameOrIpRef<'a> {
    /// Attempts to decode an encodingless string as either an ipv4 address, ipv6 address or
    /// DNS name; in that order.  In practice this space is non-overlapping because
    /// DNS name components are separated by periods but cannot be wholly numeric (so cannot
    /// overlap with a valid ipv4 address), and ipv6 addresses are separated by colons but
    /// cannot contain periods.
    ///
    /// The ipv6 address encoding supported here is extremely simplified; it does not support
    /// compression, all leading zeroes must be present in each 16-bit word, etc.  Generally
    /// this is not suitable as a parse for human-provided addresses for this reason.  Instead:
    /// consider parsing these with `std::net::IpAddr` and then using
    /// `IpAddress::from<std::net::IpAddr>`.
    pub fn try_from_ascii(dns_name_or_ip: &'a [u8]) -> Result<Self, InvalidDnsNameOrIpError> {
        if ip_address::is_valid_ipv4_address(untrusted::Input::from(dns_name_or_ip)) {
            return Ok(DnsNameOrIpRef::IpAddress(IpAddressRef::IpV4AddressRef(
                dns_name_or_ip,
                ip_address::ipv4_octets(dns_name_or_ip).map_err(|_| InvalidDnsNameOrIpError)?,
            )));
        }
        if ip_address::is_valid_ipv6_address(untrusted::Input::from(dns_name_or_ip)) {
            return Ok(DnsNameOrIpRef::IpAddress(IpAddressRef::IpV6AddressRef(
                dns_name_or_ip,
                ip_address::ipv6_octets(dns_name_or_ip).map_err(|_| InvalidDnsNameOrIpError)?,
            )));
        }
        Ok(DnsNameOrIpRef::DnsName(
            DnsNameRef::try_from_ascii(dns_name_or_ip).map_err(|_| InvalidDnsNameOrIpError)?,
        ))
    }

    /// Constructs a `DnsNameOrIpRef` from the given input if the input is a
    /// syntactically-valid DNS name or IP address.
    pub fn try_from_ascii_str(dns_name_or_ip: &'a str) -> Result<Self, InvalidDnsNameOrIpError> {
        Self::try_from_ascii(dns_name_or_ip.as_bytes())
    }
}

impl<'a> From<DnsNameRef<'a>> for DnsNameOrIpRef<'a> {
    fn from(dns_name: DnsNameRef<'a>) -> DnsNameOrIpRef {
        DnsNameOrIpRef::DnsName(DnsNameRef(dns_name.0))
    }
}

impl<'a> From<IpAddressRef<'a>> for DnsNameOrIpRef<'a> {
    fn from(dns_name: IpAddressRef<'a>) -> DnsNameOrIpRef {
        match dns_name {
            IpAddressRef::IpV4AddressRef(ip_address, ip_address_octets) => {
                DnsNameOrIpRef::IpAddress(IpAddressRef::IpV4AddressRef(
                    ip_address,
                    ip_address_octets,
                ))
            }
            IpAddressRef::IpV6AddressRef(ip_address, ip_address_octets) => {
                DnsNameOrIpRef::IpAddress(IpAddressRef::IpV6AddressRef(
                    ip_address,
                    ip_address_octets,
                ))
            }
        }
    }
}

impl AsRef<[u8]> for DnsNameOrIpRef<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            DnsNameOrIpRef::DnsName(dns_name) => dns_name.0,
            DnsNameOrIpRef::IpAddress(ip_address) => match ip_address {
                IpAddressRef::IpV4AddressRef(ip_address, _)
                | IpAddressRef::IpV6AddressRef(ip_address, _) => ip_address,
            },
        }
    }
}
