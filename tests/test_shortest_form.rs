// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;

#[test]
fn test_integer_coord_encoded_as_integer() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let token = CatTokenBuilder::new()
        .geo_coordinate(45.0, 90.0, None)
        .build();

    let cose_bytes = encode_token(&token, &alg).unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(cose_bytes.as_slice()).unwrap();
    let arr = match value {
        ciborium::Value::Tag(17, inner) => match *inner {
            ciborium::Value::Array(a) => a,
            _ => panic!("expected array"),
        },
        _ => panic!("expected tag"),
    };
    let payload_cbor = match &arr[2] {
        ciborium::Value::Bytes(b) => b.clone(),
        _ => panic!("expected bytes"),
    };
    let payload: ciborium::Value = ciborium::de::from_reader(payload_cbor.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = payload {
        for (k, v) in &map {
            if let ciborium::Value::Integer(ki) = k {
                let key_val: i64 = (*ki).try_into().unwrap();
                if key_val == 317 {
                    // catgeocoord
                    if let ciborium::Value::Array(zones) = v {
                        if let ciborium::Value::Array(zone) = &zones[0] {
                            assert!(
                                matches!(zone[0], ciborium::Value::Integer(_)),
                                "45.0 should be encoded as integer, got {:?}",
                                zone[0]
                            );
                            assert!(
                                matches!(zone[1], ciborium::Value::Integer(_)),
                                "90.0 should be encoded as integer, got {:?}",
                                zone[1]
                            );
                            return;
                        }
                    }
                }
            }
        }
        panic!("catgeocoord not found");
    }
}

#[test]
fn test_fractional_coord_encoded_as_float() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let token = CatTokenBuilder::new()
        .geo_coordinate(45.5, 90.25, None)
        .build();

    let cose_bytes = encode_token(&token, &alg).unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(cose_bytes.as_slice()).unwrap();
    let arr = match value {
        ciborium::Value::Tag(17, inner) => match *inner {
            ciborium::Value::Array(a) => a,
            _ => panic!("expected array"),
        },
        _ => panic!("expected tag"),
    };
    let payload_cbor = match &arr[2] {
        ciborium::Value::Bytes(b) => b.clone(),
        _ => panic!("expected bytes"),
    };
    let payload: ciborium::Value = ciborium::de::from_reader(payload_cbor.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = payload {
        for (k, v) in &map {
            if let ciborium::Value::Integer(ki) = k {
                let key_val: i64 = (*ki).try_into().unwrap();
                if key_val == 317 {
                    if let ciborium::Value::Array(zones) = v {
                        if let ciborium::Value::Array(zone) = &zones[0] {
                            assert!(
                                matches!(zone[0], ciborium::Value::Float(_)),
                                "45.5 should be float"
                            );
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_integer_coords_roundtrip() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let token = CatTokenBuilder::new()
        .geo_coordinate(45.0, -90.0, Some(1000))
        .build();

    let encoded = encode_token(&token, &alg).unwrap();
    let decoded = decode_token(&encoded, &alg).unwrap();
    let coords = decoded.cat.catgeocoord.unwrap();
    assert_eq!(coords[0].lat, 45.0);
    assert_eq!(coords[0].lon, -90.0);
}
