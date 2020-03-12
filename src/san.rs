use crate::{
    der::read_tag_and_get_value,
    name::{iterate_names, presented_dns_id_matches_reference_dns_id, GeneralName, NameIteration},
    Error,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Subject Alternative Name (SAN)
#[non_exhaustive]
pub enum SubjectAlternativeName {
    /// DNS name
    Dns(String),
    /// IPv4 or IPv6 address
    Ip(IpAddr),
}

impl SubjectAlternativeName {
    /// Binary OID of CommonName (CN) (id-at-commonName).
    const OID_CN: [u8; 3] = [85, 4, 3];

    fn traverse<'a>(
        input: &'a untrusted::Input, agg: &mut Vec<(u8, Vec<u8>)>,
    ) -> Result<(), Error> {
        let mut reader = untrusted::Reader::new(input.clone());
        while let Ok((tag, value)) = read_tag_and_get_value(&mut reader) {
            agg.push((tag, value.as_slice_less_safe().to_vec()));
            Self::traverse(&value.clone(), agg)?;
        }
        Ok(())
    }

    /// Strings in Rust are unicode (UTF-8), and unicode codepoints are a
    /// superset of iso-8859-1 characters. This specific conversion is
    /// actually trivial.
    fn latin1_to_string(s: &[u8]) -> String { s.iter().map(|&c| c as char).collect() }

    fn ucs4_to_string(s: &[u8]) -> Result<String, Error> {
        if s.len() % 4 == 0 {
            let mut tmp = String::with_capacity(s.len() / 4);
            for i in (0..s.len()).step_by(4) {
                match std::char::from_u32(
                    (u32::from(s[i]) << 24)
                        | (u32::from(s[i]) << 16)
                        | (u32::from(s[i]) << 8)
                        | u32::from(s[i + 1]),
                ) {
                    Some(c) => tmp.push(c),
                    _ => return Err(Error::BadDER),
                }
            }
            Ok(tmp)
        } else {
            Err(Error::BadDER)
        }
    }

    fn bmp_to_string(s: &[u8]) -> Result<String, Error> {
        if s.len() % 2 == 0 {
            let mut tmp = String::with_capacity(s.len() / 2);
            for i in (0..s.len()).step_by(2) {
                match std::char::from_u32((u32::from(s[i]) << 8) | u32::from(s[i + 1])) {
                    Some(c) => tmp.push(c),
                    _ => return Err(Error::BadDER),
                }
            }
            Ok(tmp)
        } else {
            Err(Error::BadDER)
        }
    }

    fn extract_common_name(der: &untrusted::Input) -> Option<String> {
        let mut input = vec![];
        Self::traverse(der, &mut input).unwrap();
        if let Some(oid_position) = input
            .iter()
            .position(|(tag, value)| *tag == 6u8 && value.as_slice() == Self::OID_CN)
        {
            match input.get(oid_position + 1) {
                // PrintableString (Subset of ASCII, therefore valid UTF8)
                Some((19u8, value)) => String::from_utf8(value.clone()).ok(),
                // UTF8String
                Some((12u8, value)) => String::from_utf8(value.clone()).ok(),
                // UniversalString (UCS-4 32-bit encoded)
                Some((28u8, value)) => Self::ucs4_to_string(value).ok(),
                // BMPString  (UCS-2 16-bit encoded)
                Some((30u8, value)) => Self::bmp_to_string(value).ok(),
                // VideotexString resp. TeletexString ISO-8859-1 encoded
                Some((21u8, value)) => Some(Self::latin1_to_string(value.as_slice())),
                _ => None,
            }
        } else {
            None
        }
    }

    fn matches_dns(dns: &str, name: &GeneralName) -> bool {
        let dns_input = untrusted::Input::from(dns.as_bytes());
        match name {
            GeneralName::DNSName(d) =>
                presented_dns_id_matches_reference_dns_id(d.clone(), dns_input).unwrap_or(false),
            GeneralName::DirectoryName(d) => {
                if let Some(x) = Self::extract_common_name(d) {
                    //x == dns
                    presented_dns_id_matches_reference_dns_id(
                        untrusted::Input::from(x.as_bytes()),
                        dns_input,
                    )
                    .unwrap_or(false)
                } else {
                    false
                }
            },
            _ => false,
        }
    }

    fn matches_ip(ip: &IpAddr, name: &GeneralName) -> Result<bool, untrusted::EndOfInput> {
        match name {
            GeneralName::IPAddress(d) => match ip {
                IpAddr::V4(v4) if d.len() == 4 => {
                    let mut reader = untrusted::Reader::new(d.clone());
                    let mut raw_ip_address: [u8; 4] = Default::default();
                    raw_ip_address.clone_from_slice(reader.read_bytes(4)?.as_slice_less_safe());
                    Ok(Ipv4Addr::from(raw_ip_address) == *v4)
                },
                IpAddr::V6(v6) if d.len() == 16 => {
                    let mut reader = untrusted::Reader::new(d.clone());
                    let mut raw_ip_address: [u8; 16] = Default::default();
                    raw_ip_address.clone_from_slice(reader.read_bytes(16)?.as_slice_less_safe());
                    Ok(Ipv6Addr::from(raw_ip_address) == *v6)
                },
                _ => Ok(false),
            },
            GeneralName::DirectoryName(d) =>
                if let Some(x) = Self::extract_common_name(d) {
                    match IpAddr::from_str(x.as_str()) {
                        Ok(a) => Ok(a == *ip),
                        Err(_) => Ok(false),
                    }
                } else {
                    Ok(false)
                },
            _ => Ok(false),
        }
    }

    fn matches(&self, _cert: &super::EndEntityCert, name: &GeneralName) -> Result<bool, Error> {
        match self {
            SubjectAlternativeName::Dns(d) => Ok(Self::matches_dns(d, name)),
            SubjectAlternativeName::Ip(ip) => Self::matches_ip(ip, name).map_err(|_| Error::BadDER),
            //_ => Ok(false),
        }
    }

    /// Check if this name is the subject of the provided certificate.
    pub fn is_subject_of_legacy(
        &self, cert: &super::EndEntityCert, check_cn: bool,
    ) -> Result<(), Error> {
        let crt = &cert.inner;
        iterate_names(
            if check_cn { Some(crt.subject) } else { None },
            crt.subject_alt_name,
            Err(Error::CertNotValidForName),
            &|name| match self.matches(cert, &name) {
                Ok(true) => NameIteration::Stop(Ok(())),
                Ok(false) => NameIteration::KeepGoing,
                Err(e) => NameIteration::Stop(Err(e)),
            },
        )
    }

    /// Check if this name is the subject of the provided certificate.
    pub fn is_subject_of(&self, cert: &super::EndEntityCert) -> Result<(), Error> {
        self.is_subject_of_legacy(cert, false)
    }
}
