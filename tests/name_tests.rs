use ring::test::{compile_time_assert_send, compile_time_assert_sync};
use webpki::DnsNameRef;

#[test]
fn test_dns_name_ref_traits() {
    compile_time_assert_send::<DnsNameRef>();
    compile_time_assert_sync::<DnsNameRef>();

    let a = DnsNameRef::try_from_ascii(b"example.com").unwrap();

    // `Copy`
    {
        let _b = a;
        let _c = a;
    }

    // `Clone`
    #[allow(clippy::clone_on_copy)]
    let _ = a.clone();
    // TODO: verify the clone is the same as `a`.

    // TODO: Don't require `alloc` for these.
    #[cfg(feature = "alloc")]
    {
        // `Debug`.
        assert_eq!(format!("{:?}", &a), "DnsNameRef(\"example.com\")");
    }
}
