#[cfg(feature = "std")]
mod tests {

    use std::net::{IpAddr, Ipv4Addr};
    use webpki::SubjectAlternativeName;

    #[test]
    fn dns_in_cn() {
        let der = include_bytes!("san/dns_in_cn.der");
        let cert = webpki::EndEntityCert::from(der).unwrap();
        let name = SubjectAlternativeName::Dns("example.com".to_string());
        assert_eq!(name.is_subject_of(&cert), Ok(()));
    }

    #[test]
    fn dns_wildcard_in_cn() {
        let der = include_bytes!("san/dns_wildcard_in_cn.der");
        let cert = webpki::EndEntityCert::from(der).unwrap();
        let name = SubjectAlternativeName::Dns("sub.example.com".to_string());
        assert_eq!(name.is_subject_of(&cert), Ok(()));
    }

    #[test]
    fn dns_in_san() {
        let der = include_bytes!("san/dns_in_san.der");
        let cert = webpki::EndEntityCert::from(der).unwrap();
        let name = SubjectAlternativeName::Dns("example.org".to_string());
        assert_eq!(name.is_subject_of(&cert), Ok(()));
    }

    #[test]
    fn dns_wildcard_in_san() {
        let der = include_bytes!("san/dns_wildcard_in_san.der");
        let cert = webpki::EndEntityCert::from(der).unwrap();
        let name = SubjectAlternativeName::Dns("sub.example.org".to_string());
        assert_eq!(name.is_subject_of(&cert), Ok(()));
    }

    #[test]
    fn ip_in_cn() {
        let der = include_bytes!("san/ip_in_cn.der");
        let cert = webpki::EndEntityCert::from(der).unwrap();
        let name = SubjectAlternativeName::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(name.is_subject_of(&cert), Ok(()));
    }

    #[test]
    fn ip_in_san() {
        let der = include_bytes!("san/ip_in_san.der");
        let cert = webpki::EndEntityCert::from(der).unwrap();
        let name = SubjectAlternativeName::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(name.is_subject_of(&cert), Ok(()));
    }
}
