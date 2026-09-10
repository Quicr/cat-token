// Tests for CTA-5007-B §4.6.15: catgeocoord as array-of-arrays with u32 radius.

use cat_token::*;

#[test]
fn test_single_zone_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_geo_coordinate(37.7749, -122.4194, 500);

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = Decoder::with_algorithm(&algorithm)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    let coords = decoded.cat.catgeocoord.unwrap();
    assert_eq!(coords.len(), 1);
    assert!((coords[0].lat - 37.7749).abs() < 0.001);
    assert!((coords[0].lon - (-122.4194)).abs() < 0.001);
    assert_eq!(coords[0].radius, 500);
}

#[test]
fn test_multiple_zones() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_geo_coordinate(37.7749, -122.4194, 1000)
        .with_geo_coordinate(40.7128, -74.0060, 2000);

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = Decoder::with_algorithm(&algorithm)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    let coords = decoded.cat.catgeocoord.unwrap();
    assert_eq!(coords.len(), 2);
    assert!((coords[0].lat - 37.7749).abs() < 0.001);
    assert!((coords[1].lat - 40.7128).abs() < 0.001);
}

#[test]
fn test_with_geo_coordinates_bulk() {
    let coords = vec![
        GeoCoordinate::new(35.6762, 139.6503, 500),
        GeoCoordinate::new(48.8566, 2.3522, 1000),
        GeoCoordinate::new(-33.8688, 151.2093, 0),
    ];

    let token = CatTokenBuilder::new()
        .geo_coordinates(coords.clone())
        .build()
        .unwrap();

    assert_eq!(token.cat.catgeocoord.as_ref().unwrap().len(), 3);
    assert_eq!(token.cat.catgeocoord, Some(coords));
}

#[test]
fn test_radius_is_unsigned_integer() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_geo_coordinate(0.0, 0.0, u32::MAX);

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = Decoder::with_algorithm(&algorithm)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    let coords = decoded.cat.catgeocoord.unwrap();
    assert_eq!(coords[0].radius, u32::MAX);
}

#[test]
fn test_validator_rejects_invalid_coordinates() {
    let validator = CatTokenValidator::new().dangerously_allow_unencrypted_privacy_claims();

    let mut token = CatToken::new();
    token.cat.catgeocoord = Some(vec![GeoCoordinate::new(91.0, 0.0, 0)]);

    assert!(matches!(
        validator.validate(&token),
        Err(CatError::GeographicValidationFailed(_))
    ));
}

#[test]
fn test_validator_rejects_invalid_in_any_zone() {
    let validator = CatTokenValidator::new().dangerously_allow_unencrypted_privacy_claims();

    let mut token = CatToken::new();
    token.cat.catgeocoord = Some(vec![
        GeoCoordinate::new(37.0, -122.0, 0),
        GeoCoordinate::new(0.0, 200.0, 0),
    ]);

    assert!(matches!(
        validator.validate(&token),
        Err(CatError::GeographicValidationFailed(_))
    ));
}
