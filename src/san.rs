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
    fn latin1_to_string(s: &[u8]) -> String {
        s.iter().map(|&c| c as char).collect()
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
                // Some((28u8, value)) => unimplemented!(),
                // BMPString  (UCS-2 16-bit encoded)
                //Some((30u8, value)) => unimplemented!(),
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
            GeneralName::DNSName(d) => {
                presented_dns_id_matches_reference_dns_id(d.clone(), dns_input).unwrap_or(false)
            }
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
            }
            _ => false,
        }
    }

    fn matches_ip(ip: &IpAddr, name: &GeneralName) -> Result<bool, untrusted::EndOfInput> {
        match name {
            GeneralName::IPAddress(d) => match ip {
                IpAddr::V4(v4) if d.len() == 4 => {
                    let mut reader = untrusted::Reader::new(d.clone());
                    let a = reader.read_byte()?;
                    let b = reader.read_byte()?;
                    let c = reader.read_byte()?;
                    let d = reader.read_byte()?;
                    Ok(Ipv4Addr::from([a, b, c, d]) == *v4)
                }
                IpAddr::V6(v6) if d.len() == 16 => {
                    let mut reader = untrusted::Reader::new(d.clone());
                    let a = reader.read_byte()?;
                    let b = reader.read_byte()?;
                    let c = reader.read_byte()?;
                    let d = reader.read_byte()?;
                    let e = reader.read_byte()?;
                    let f = reader.read_byte()?;
                    let g = reader.read_byte()?;
                    let h = reader.read_byte()?;
                    let i = reader.read_byte()?;
                    let j = reader.read_byte()?;
                    let k = reader.read_byte()?;
                    let l = reader.read_byte()?;
                    let m = reader.read_byte()?;
                    let n = reader.read_byte()?;
                    let o = reader.read_byte()?;
                    let p = reader.read_byte()?;
                    Ok(Ipv6Addr::from([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p]) == *v6)
                }
                _ => Ok(false),
            },
            GeneralName::DirectoryName(d) => {
                if let Some(x) = Self::extract_common_name(d) {
                    match IpAddr::from_str(x.as_str()) {
                        Ok(a) => Ok(a == *ip),
                        Err(_) => Ok(false),
                    }
                } else {
                    Ok(false)
                }
            }
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
    pub fn is_subject_of(&self, cert: &super::EndEntityCert) -> Result<(), Error> {
        let crt = &cert.inner;
        iterate_names(
            crt.subject,
            crt.subject_alt_name,
            Err(Error::CertNotValidForName),
            &|name| match self.matches(cert, &name) {
                Ok(true) => NameIteration::Stop(Ok(())),
                Ok(false) => NameIteration::KeepGoing,
                Err(e) => NameIteration::Stop(Err(e)),
            },
        )
    }
}
