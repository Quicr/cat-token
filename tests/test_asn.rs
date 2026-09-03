// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn test_network_identifier_types() {
    let ip = NetworkIdentifier::IpAddress(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    let ip_prefix = NetworkIdentifier::IpPrefix(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 24);
    let asn = NetworkIdentifier::Asn(64512);
    let asn_range = NetworkIdentifier::AsnRange(64512, 65534);

    match ip {
        NetworkIdentifier::IpAddress(addr) => {
            assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        }
        _ => panic!("Expected IpAddress"),
    }

    match ip_prefix {
        NetworkIdentifier::IpPrefix(addr, prefix) => {
            assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
            assert_eq!(prefix, 24);
        }
        _ => panic!("Expected IpPrefix"),
    }

    match asn {
        NetworkIdentifier::Asn(num) => assert_eq!(num, 64512),
        _ => panic!("Expected Asn"),
    }

    match asn_range {
        NetworkIdentifier::AsnRange(start, end) => {
            assert_eq!(start, 64512);
            assert_eq!(end, 65534);
        }
        _ => panic!("Expected AsnRange"),
    }
}

#[test]
fn test_network_identifier_from_str() {
    let ip = NetworkIdentifier::from_ip_str("192.168.1.1").unwrap();
    assert!(matches!(ip, NetworkIdentifier::IpAddress(IpAddr::V4(_))));

    let ip6 = NetworkIdentifier::from_ip_str("2001:db8::1").unwrap();
    assert!(matches!(ip6, NetworkIdentifier::IpAddress(IpAddr::V6(_))));

    let prefix = NetworkIdentifier::from_cidr_str("10.0.0.0/8").unwrap();
    assert!(matches!(prefix, NetworkIdentifier::IpPrefix(_, 8)));

    assert!(NetworkIdentifier::from_ip_str("not-an-ip").is_err());
    assert!(NetworkIdentifier::from_cidr_str("10.0.0.0").is_err());
    assert!(NetworkIdentifier::from_cidr_str("10.0.0.0/33").is_err());
}

#[test]
fn test_token_with_network_identifiers() {
    let nips = vec![
        NetworkIdentifier::IpAddress(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        NetworkIdentifier::IpPrefix(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 16),
        NetworkIdentifier::Asn(65001),
        NetworkIdentifier::AsnRange(64512, 65534),
    ];

    let token = CatToken::new().with_network_identifiers(nips.clone());
    assert_eq!(token.cat.catnip, Some(nips));
}

#[test]
fn test_token_builder_network_methods() {
    let token = CatTokenBuilder::new()
        .ip_address("203.0.113.1")
        .ip_range("198.51.100.0/24")
        .asn(64496)
        .asn_range(65000, 65010)
        .build();

    assert!(token.cat.catnip.is_some());
    let nips = token.cat.catnip.unwrap();
    assert_eq!(nips.len(), 4);

    assert!(nips.iter().any(|nip| matches!(nip,
        NetworkIdentifier::IpAddress(addr) if *addr == IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))));
    assert!(nips.iter().any(|nip| matches!(nip,
        NetworkIdentifier::IpPrefix(addr, 24) if *addr == IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)))));
    assert!(
        nips.iter()
            .any(|nip| matches!(nip, NetworkIdentifier::Asn(64496)))
    );
    assert!(
        nips.iter()
            .any(|nip| matches!(nip, NetworkIdentifier::AsnRange(65000, 65010)))
    );
}

#[test]
fn test_incremental_network_identifier_building() {
    let mut token = CatToken::new();

    token = token.with_ip_address("10.1.1.1");
    assert_eq!(token.cat.catnip.as_ref().unwrap().len(), 1);

    token = token.with_asn(65001);
    assert_eq!(token.cat.catnip.as_ref().unwrap().len(), 2);

    token = token.with_ip_range("192.168.0.0/16");
    assert_eq!(token.cat.catnip.as_ref().unwrap().len(), 3);

    token = token.with_asn_range(64512, 64520);
    assert_eq!(token.cat.catnip.as_ref().unwrap().len(), 4);
}

#[test]
fn test_network_identifier_cwt_encoding_decoding() {
    let original_nips = vec![
        NetworkIdentifier::IpAddress(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42))),
        NetworkIdentifier::IpPrefix(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24),
        NetworkIdentifier::Asn(64512),
        NetworkIdentifier::AsnRange(65000, 65010),
    ];

    let original_token = CatToken::new()
        .with_issuer("https://asn.test.com")
        .with_network_identifiers(original_nips.clone());

    let cwt = Cwt::new(ALG_ES256, original_token.clone());
    let encoded_payload = cwt.encode_payload().unwrap();
    let decoded_token = Cwt::decode_payload(&encoded_payload).unwrap();

    assert_eq!(decoded_token.core.iss, original_token.core.iss);
    assert_eq!(decoded_token.cat.catnip, original_token.cat.catnip);
}

#[test]
fn test_ipv6_encoding_decoding() {
    let nips = vec![
        NetworkIdentifier::IpAddress(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        NetworkIdentifier::IpPrefix(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            32,
        ),
    ];

    let token = CatToken::new().with_network_identifiers(nips.clone());
    let cwt = Cwt::new(ALG_ES256, token);
    let encoded = cwt.encode_payload().unwrap();
    let decoded = Cwt::decode_payload(&encoded).unwrap();

    let decoded_nips = decoded.cat.catnip.unwrap();
    assert_eq!(decoded_nips.len(), 2);
    assert!(matches!(
        &decoded_nips[0],
        NetworkIdentifier::IpAddress(IpAddr::V6(_))
    ));
    assert!(matches!(
        &decoded_nips[1],
        NetworkIdentifier::IpPrefix(IpAddr::V6(_), 32)
    ));
}

#[test]
fn test_asn_validation_ranges() {
    let valid_asns = vec![1, 64512, 65534, 4200000000];

    for asn in valid_asns {
        let nip = NetworkIdentifier::Asn(asn);
        let token = CatToken::new().with_network_identifiers(vec![nip]);
        assert!(token.cat.catnip.is_some());
    }

    let token = CatToken::new().with_asn_range(64512, 65534);
    if let Some(nips) = &token.cat.catnip
        && let NetworkIdentifier::AsnRange(start, end) = &nips[0]
    {
        assert!(start < end);
        assert!(*start >= 1);
    }
}

#[test]
fn test_mixed_network_identifiers_comprehensive() {
    let token = CatTokenBuilder::new()
        .issuer("https://network.example.com")
        .version(1)
        .ip_address("192.168.1.1")
        .ip_address("10.0.0.1")
        .ip_range("172.16.0.0/16")
        .ip_range("192.168.0.0/24")
        .asn(64496)
        .asn(65001)
        .asn_range(64512, 64520)
        .asn_range(65000, 65010)
        .build();

    assert_eq!(token.cat.catv, Some(1));
    let nips = token.cat.catnip.unwrap();
    assert_eq!(nips.len(), 8);

    let mut ip_count = 0;
    let mut prefix_count = 0;
    let mut asn_count = 0;
    let mut asn_range_count = 0;

    for nip in &nips {
        match nip {
            NetworkIdentifier::IpAddress(_) => ip_count += 1,
            NetworkIdentifier::IpPrefix(_, _) => prefix_count += 1,
            NetworkIdentifier::Asn(_) => asn_count += 1,
            NetworkIdentifier::AsnRange(_, _) => asn_range_count += 1,
        }
    }

    assert_eq!(ip_count, 2);
    assert_eq!(prefix_count, 2);
    assert_eq!(asn_count, 2);
    assert_eq!(asn_range_count, 2);
}

#[test]
fn test_empty_network_identifiers() {
    let token = CatToken::new();
    assert!(token.cat.catnip.is_none());

    let token_with_empty = CatToken::new().with_network_identifiers(vec![]);
    assert_eq!(token_with_empty.cat.catnip, Some(vec![]));
}
