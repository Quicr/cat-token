// Tests for CTA-5007-B §4.6.15: catgeocoord as array-of-arrays with u32 radius.

use cat_token::*;

#[test]
fn test_single_zone_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_geo_coordinate(37.7749, -122.4194, Some(500));

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let coords = decoded.cat.catgeocoord.unwrap();
    assert_eq!(coords.len(), 1);
    assert!((coords[0].lat - 37.7749).abs() < 0.001);
    assert!((coords[0].lon - (-122.4194)).abs() < 0.001);
    assert_eq!(coords[0].radius, Some(500));
}

#[test]
fn test_multiple_zones() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_geo_coordinate(37.7749, -122.4194, Some(1000))
        .with_geo_coordinate(40.7128, -74.0060, Some(2000));

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let coords = decoded.cat.catgeocoord.unwrap();
    assert_eq!(coords.len(), 2);
    assert!((coords[0].lat - 37.7749).abs() < 0.001);
    assert!((coords[1].lat - 40.7128).abs() < 0.001);
}

#[test]
fn test_zone_without_radius() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_geo_coordinate(51.5074, -0.1278, None);

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let coords = decoded.cat.catgeocoord.unwrap();
    assert_eq!(coords.len(), 1);
    assert_eq!(coords[0].radius, None);
}

#[test]
fn test_with_geo_coordinates_bulk() {
    let coords = vec![
        GeoCoordinate { lat: 35.6762, lon: 139.6503, radius: Some(500) },
        GeoCoordinate { lat: 48.8566, lon: 2.3522, radius: Some(1000) },
        GeoCoordinate { lat: -33.8688, lon: 151.2093, radius: None },
    ];

    let token = CatTokenBuilder::new()
        .geo_coordinates(coords.clone())
        .build();

    assert_eq!(token.cat.catgeocoord.as_ref().unwrap().len(), 3);
    assert_eq!(token.cat.catgeocoord, Some(coords));
}

#[test]
fn test_radius_is_unsigned_integer() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_geo_coordinate(0.0, 0.0, Some(u32::MAX));

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let coords = decoded.cat.catgeocoord.unwrap();
    assert_eq!(coords[0].radius, Some(u32::MAX));
}

#[test]
fn test_validator_rejects_invalid_coordinates() {
    let validator = CatTokenValidator::new();

    let mut token = CatToken::new();
    token.cat.catgeocoord = Some(vec![GeoCoordinate {
        lat: 91.0,
        lon: 0.0,
        radius: None,
    }]);

    assert!(matches!(
        validator.validate(&token),
        Err(CatError::GeographicValidationFailed(_))
    ));
}

#[test]
fn test_validator_rejects_invalid_in_any_zone() {
    let validator = CatTokenValidator::new();

    let mut token = CatToken::new();
    token.cat.catgeocoord = Some(vec![
        GeoCoordinate { lat: 37.0, lon: -122.0, radius: None },
        GeoCoordinate { lat: 0.0, lon: 200.0, radius: None },
    ]);

    assert!(matches!(
        validator.validate(&token),
        Err(CatError::GeographicValidationFailed(_))
    ));
}
