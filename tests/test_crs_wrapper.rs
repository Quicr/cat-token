// Tests for CBOR tag 279 CRS Wrapper support (CTA-5007-B §4.6.15-17).

use cat_token::*;

fn encode_with_crs_tag(claim_key: i64, crs_id: u64, inner_value: ciborium::Value) -> Vec<u8> {
    let map = ciborium::Value::Map(vec![(
        ciborium::Value::Integer(claim_key.into()),
        ciborium::Value::Tag(
            279,
            Box::new(ciborium::Value::Array(vec![
                ciborium::Value::Integer(crs_id.into()),
                inner_value,
            ])),
        ),
    )]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).unwrap();
    buf
}

#[test]
fn test_catgeocoord_with_wgs84_crs_wrapper() {
    let coord_array = ciborium::Value::Array(vec![ciborium::Value::Array(vec![
        ciborium::Value::Float(37.7749),
        ciborium::Value::Float(-122.4194),
    ])]);

    let cbor = encode_with_crs_tag(CLAIM_CATGEOCOORD, 0, coord_array);
    let token = Cwt::decode_payload(&cbor).unwrap();

    let coords = token.cat.catgeocoord.unwrap();
    assert_eq!(coords.len(), 1);
    assert!((coords[0].lat - 37.7749).abs() < 0.001);
    assert!((coords[0].lon - (-122.4194)).abs() < 0.001);
}

#[test]
fn test_catgeocoord_rejects_unsupported_crs() {
    let coord_array = ciborium::Value::Array(vec![ciborium::Value::Array(vec![
        ciborium::Value::Float(37.7749),
        ciborium::Value::Float(-122.4194),
    ])]);

    let cbor = encode_with_crs_tag(CLAIM_CATGEOCOORD, 99, coord_array);
    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_err());
    match result {
        Err(CatError::InvalidClaimValue(msg)) => {
            assert!(msg.contains("Unsupported CRS"), "Error: {msg}");
        }
        other => panic!("Expected InvalidClaimValue, got: {other:?}"),
    }
}

#[test]
fn test_geohash_with_wgs84_crs_wrapper() {
    let geohash_val = ciborium::Value::Text("9q8yyk".to_string());
    let cbor = encode_with_crs_tag(CLAIM_GEOHASH, 0, geohash_val);
    let token = Cwt::decode_payload(&cbor).unwrap();

    assert_eq!(token.cat.geohash, Some(vec!["9q8yyk".to_string()]));
}

#[test]
fn test_geohash_array_with_crs_wrapper() {
    let geohash_arr = ciborium::Value::Array(vec![
        ciborium::Value::Text("9q8yyk".to_string()),
        ciborium::Value::Text("dr5regw".to_string()),
    ]);
    let cbor = encode_with_crs_tag(CLAIM_GEOHASH, 0, geohash_arr);
    let token = Cwt::decode_payload(&cbor).unwrap();

    assert_eq!(
        token.cat.geohash,
        Some(vec!["9q8yyk".to_string(), "dr5regw".to_string()])
    );
}

#[test]
fn test_geohash_rejects_unsupported_crs() {
    let geohash_val = ciborium::Value::Text("9q8yyk".to_string());
    let cbor = encode_with_crs_tag(CLAIM_GEOHASH, 1, geohash_val);
    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_err());
}

#[test]
fn test_catgeoalt_with_wgs84_crs_wrapper() {
    let alt_arr = ciborium::Value::Array(vec![
        ciborium::Value::Float(100.5),
        ciborium::Value::Float(5.0),
    ]);
    let cbor = encode_with_crs_tag(CLAIM_CATGEOALT, 0, alt_arr);
    let token = Cwt::decode_payload(&cbor).unwrap();

    let alt = token.cat.catgeoalt.unwrap();
    assert!((alt.altitude - 100.5).abs() < 0.001);
    assert!((alt.deviation - 5.0).abs() < 0.001);
}

#[test]
fn test_catgeoalt_rejects_unsupported_crs() {
    let alt_arr = ciborium::Value::Array(vec![
        ciborium::Value::Float(100.5),
        ciborium::Value::Float(5.0),
    ]);
    let cbor = encode_with_crs_tag(CLAIM_CATGEOALT, 42, alt_arr);
    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_err());
}

#[test]
fn test_catgeocoord_without_crs_wrapper_still_works() {
    let token = CatToken::new().with_geo_coordinate(37.7749, -122.4194, Some(10));

    let cwt = Cwt::new(-7, token);
    let encoded = cwt.encode_payload().unwrap();
    let decoded = Cwt::decode_payload(&encoded).unwrap();

    let coords = decoded.cat.catgeocoord.unwrap();
    assert!((coords[0].lat - 37.7749).abs() < 0.001);
}

#[test]
fn test_crs_wrapper_invalid_structure() {
    // tag 279 wrapping a non-array
    let map = ciborium::Value::Map(vec![(
        ciborium::Value::Integer(CLAIM_CATGEOCOORD.into()),
        ciborium::Value::Tag(279, Box::new(ciborium::Value::Text("bad".to_string()))),
    )]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).unwrap();

    let result = Cwt::decode_payload(&buf);
    assert!(result.is_err());
}
