// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;

#[test]
fn test_network_identifier_types() {
    let ip = NetworkIdentifier::IpAddress("192.168.1.1".to_string());
    let ip_range = NetworkIdentifier::IpRange("192.168.0.0/24".to_string());
    let asn = NetworkIdentifier::Asn(64512);
    let asn_range = NetworkIdentifier::AsnRange(64512, 65534);

    match ip {
        NetworkIdentifier::IpAddress(addr) => assert_eq!(addr, "192.168.1.1"),
        _ => panic!("Expected IpAddress"),
    }

    match ip_range {
        NetworkIdentifier::IpRange(range) => assert_eq!(range, "192.168.0.0/24"),
        _ => panic!("Expected IpRange"),
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
fn test_token_with_network_identifiers() {
    let nips = vec![
        NetworkIdentifier::IpAddress("10.0.0.1".to_string()),
        NetworkIdentifier::IpRange("172.16.0.0/16".to_string()),
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

    // Check each network identifier
    assert!(
        nips.iter()
            .any(|nip| matches!(nip, NetworkIdentifier::IpAddress(ip) if ip == "203.0.113.1"))
    );
    assert!(
        nips.iter().any(
            |nip| matches!(nip, NetworkIdentifier::IpRange(range) if range == "198.51.100.0/24")
        )
    );
    assert!(
        nips.iter()
            .any(|nip| matches!(nip, NetworkIdentifier::Asn(asn) if *asn == 64496))
    );
    assert!(nips.iter().any(|nip| matches!(nip, NetworkIdentifier::AsnRange(start, end) if *start == 65000 && *end == 65010)));
}

#[test]
fn test_incremental_network_identifier_building() {
    let mut token = CatToken::new();

    // Add network identifiers incrementally
    token = token.with_ip_address("10.1.1.1");
    assert_eq!(token.cat.catnip.as_ref().unwrap().len(), 1);

    token = token.with_asn(65001);
    assert_eq!(token.cat.catnip.as_ref().unwrap().len(), 2);

    token = token.with_ip_range("192.168.0.0/16");
    assert_eq!(token.cat.catnip.as_ref().unwrap().len(), 3);

    token = token.with_asn_range(64512, 64520);
    assert_eq!(token.cat.catnip.as_ref().unwrap().len(), 4);

    let nips = token.cat.catnip.unwrap();
    assert!(
        nips.iter()
            .any(|nip| matches!(nip, NetworkIdentifier::IpAddress(ip) if ip == "10.1.1.1"))
    );
    assert!(
        nips.iter()
            .any(|nip| matches!(nip, NetworkIdentifier::Asn(asn) if *asn == 65001))
    );
    assert!(
        nips.iter().any(
            |nip| matches!(nip, NetworkIdentifier::IpRange(range) if range == "192.168.0.0/16")
        )
    );
    assert!(nips.iter().any(|nip| matches!(nip, NetworkIdentifier::AsnRange(start, end) if *start == 64512 && *end == 64520)));
}

#[test]
fn test_network_identifier_cwt_encoding_decoding() {
    let original_nips = vec![
        NetworkIdentifier::IpAddress("203.0.113.42".to_string()),
        NetworkIdentifier::IpRange("198.51.100.0/24".to_string()),
        NetworkIdentifier::Asn(64512),
        NetworkIdentifier::AsnRange(65000, 65010),
    ];

    let original_token = CatToken::new()
        .with_issuer("https://asn.test.com")
        .with_network_identifiers(original_nips.clone());

    let cwt = Cwt::new(-7, original_token.clone());

    // Test encoding
    let encoded_payload = cwt.encode_payload().expect("Should encode successfully");
    assert!(!encoded_payload.is_empty());

    // Test decoding
    let decoded_token = Cwt::decode_payload(&encoded_payload).expect("Should decode successfully");

    // Verify decoded network identifiers match original
    assert_eq!(decoded_token.core.iss, original_token.core.iss);
    assert_eq!(decoded_token.cat.catnip, original_token.cat.catnip);

    let decoded_nips = decoded_token.cat.catnip.unwrap();
    assert_eq!(decoded_nips.len(), 4);

    assert!(
        decoded_nips
            .iter()
            .any(|nip| matches!(nip, NetworkIdentifier::IpAddress(ip) if ip == "203.0.113.42"))
    );
    assert!(
        decoded_nips.iter().any(
            |nip| matches!(nip, NetworkIdentifier::IpRange(range) if range == "198.51.100.0/24")
        )
    );
    assert!(
        decoded_nips
            .iter()
            .any(|nip| matches!(nip, NetworkIdentifier::Asn(asn) if *asn == 64512))
    );
    assert!(decoded_nips.iter().any(|nip| matches!(nip, NetworkIdentifier::AsnRange(start, end) if *start == 65000 && *end == 65010)));
}

#[test]
fn test_asn_validation_ranges() {
    // Test valid ASN ranges
    let valid_asns = vec![
        1, 64512, 65534, 4200000000, // Valid ASN numbers
    ];

    for asn in valid_asns {
        let nip = NetworkIdentifier::Asn(asn);
        let token = CatToken::new().with_network_identifiers(vec![nip]);
        assert!(token.cat.catnip.is_some());
    }

    // Test ASN range validation
    let token = CatToken::new().with_asn_range(64512, 65534);
    if let Some(nips) = &token.cat.catnip
        && let NetworkIdentifier::AsnRange(start, end) = &nips[0]
    {
        assert!(start < end, "ASN range start should be less than end");
        assert!(*start >= 1, "ASN should be at least 1");
    }
}

#[test]
fn test_mixed_network_identifiers_comprehensive() {
    let token = CatTokenBuilder::new()
        .issuer("https://network.example.com")
        .version(1)
        // IPv4 addresses
        .ip_address("192.168.1.1")
        .ip_address("10.0.0.1")
        // IPv4 ranges
        .ip_range("172.16.0.0/16")
        .ip_range("192.168.0.0/24")
        // ASNs
        .asn(64496) // RFC 5398 documentation ASN
        .asn(65001) // Private ASN
        // ASN ranges
        .asn_range(64512, 64520) // Small private range
        .asn_range(65000, 65010) // Another private range
        .build();

    assert_eq!(
        token.core.iss,
        Some("https://network.example.com".to_string())
    );
    assert_eq!(token.cat.catv, Some(1));

    let nips = token.cat.catnip.unwrap();
    assert_eq!(nips.len(), 8);

    // Count each type
    let mut ip_count = 0;
    let mut ip_range_count = 0;
    let mut asn_count = 0;
    let mut asn_range_count = 0;

    for nip in &nips {
        match nip {
            NetworkIdentifier::IpAddress(_) => ip_count += 1,
            NetworkIdentifier::IpRange(_) => ip_range_count += 1,
            NetworkIdentifier::Asn(_) => asn_count += 1,
            NetworkIdentifier::AsnRange(_, _) => asn_range_count += 1,
        }
    }

    assert_eq!(ip_count, 2);
    assert_eq!(ip_range_count, 2);
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
