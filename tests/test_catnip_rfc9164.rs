// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn test_ipv4_address_uses_tag_52() {
    let token = CatToken::new().with_ip_address("192.168.1.100");

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = value {
        for (k, v) in &map {
            if let ciborium::Value::Integer(key_int) = k {
                let key_val: i64 = (*key_int).try_into().unwrap();
                if key_val == 311 {
                    // CLAIM_CATNIP
                    if let ciborium::Value::Array(arr) = v {
                        assert_eq!(arr.len(), 1);
                        if let ciborium::Value::Tag(tag, inner) = &arr[0] {
                            assert_eq!(*tag, 52, "IPv4 address must use CBOR tag 52");
                            if let ciborium::Value::Bytes(bytes) = inner.as_ref() {
                                assert_eq!(bytes.len(), 4, "IPv4 address must be 4 bytes");
                                assert_eq!(bytes, &[192, 168, 1, 100]);
                            } else {
                                panic!("Inner value must be bstr");
                            }
                        } else {
                            panic!("Expected tagged value, got {:?}", arr[0]);
                        }
                        return;
                    }
                }
            }
        }
    }
    panic!("catnip claim not found");
}

#[test]
fn test_ipv6_address_uses_tag_54() {
    let token = CatToken::new().with_network_identifiers(vec![NetworkIdentifier::IpAddress(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    )]);

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = value {
        for (k, v) in &map {
            if let ciborium::Value::Integer(key_int) = k {
                let key_val: i64 = (*key_int).try_into().unwrap();
                if key_val == 311 {
                    if let ciborium::Value::Array(arr) = v {
                        if let ciborium::Value::Tag(tag, inner) = &arr[0] {
                            assert_eq!(*tag, 54, "IPv6 address must use CBOR tag 54");
                            if let ciborium::Value::Bytes(bytes) = inner.as_ref() {
                                assert_eq!(bytes.len(), 16, "IPv6 address must be 16 bytes");
                            } else {
                                panic!("Inner value must be bstr");
                            }
                        } else {
                            panic!("Expected tagged value");
                        }
                        return;
                    }
                }
            }
        }
    }
    panic!("catnip claim not found");
}

#[test]
fn test_ipv4_prefix_tagged_map() {
    let token = CatToken::new().with_ip_range("10.0.0.0/8");

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = value {
        for (k, v) in &map {
            if let ciborium::Value::Integer(key_int) = k {
                let key_val: i64 = (*key_int).try_into().unwrap();
                if key_val == 311 {
                    if let ciborium::Value::Array(arr) = v {
                        if let ciborium::Value::Tag(tag, inner) = &arr[0] {
                            assert_eq!(*tag, 52, "IPv4 prefix must use CBOR tag 52");
                            if let ciborium::Value::Map(prefix_map) = inner.as_ref() {
                                assert_eq!(prefix_map.len(), 1);
                                let (k, v) = &prefix_map[0];
                                if let ciborium::Value::Integer(prefix_len) = k {
                                    let pl: i64 = (*prefix_len).try_into().unwrap();
                                    assert_eq!(pl, 8);
                                }
                                if let ciborium::Value::Bytes(prefix_bytes) = v {
                                    assert_eq!(prefix_bytes.len(), 1, "/8 prefix needs 1 byte");
                                    assert_eq!(prefix_bytes[0], 10);
                                }
                            } else {
                                panic!("Prefix must be encoded as map");
                            }
                        }
                        return;
                    }
                }
            }
        }
    }
    panic!("catnip claim not found");
}

#[test]
fn test_asn_is_bare_uint() {
    let token = CatToken::new().with_asn(64512);

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = value {
        for (k, v) in &map {
            if let ciborium::Value::Integer(key_int) = k {
                let key_val: i64 = (*key_int).try_into().unwrap();
                if key_val == 311 {
                    if let ciborium::Value::Array(arr) = v {
                        assert!(
                            matches!(&arr[0], ciborium::Value::Integer(_)),
                            "ASN must be a bare unsigned integer, got {:?}",
                            arr[0]
                        );
                        return;
                    }
                }
            }
        }
    }
    panic!("catnip claim not found");
}

#[test]
fn test_full_catnip_roundtrip() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .ip_address("192.168.1.1")
        .ip_address("2001:db8::1")
        .ip_range("10.0.0.0/8")
        .ip_range("2001:db8::/32")
        .asn(64512)
        .asn_range(65000, 65100)
        .expires_in(3600)
        .build();

    let encoded = encode_token(&token, &alg).unwrap();
    let decoded = decode_token(&encoded, &alg).unwrap();

    let nips = decoded.cat.catnip.unwrap();
    assert_eq!(nips.len(), 6);

    assert!(
        matches!(&nips[0], NetworkIdentifier::IpAddress(IpAddr::V4(v4)) if *v4 == Ipv4Addr::new(192, 168, 1, 1))
    );
    assert!(matches!(
        &nips[1],
        NetworkIdentifier::IpAddress(IpAddr::V6(_))
    ));
    assert!(matches!(
        &nips[2],
        NetworkIdentifier::IpPrefix(IpAddr::V4(_), 8)
    ));
    assert!(matches!(
        &nips[3],
        NetworkIdentifier::IpPrefix(IpAddr::V6(_), 32)
    ));
    assert!(matches!(&nips[4], NetworkIdentifier::Asn(64512)));
    assert!(matches!(
        &nips[5],
        NetworkIdentifier::AsnRange(65000, 65100)
    ));
}
