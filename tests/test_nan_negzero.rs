// Tests for CTA-5007-B §4.5: NaN and negative zero MUST NOT be used in CBOR.

use cat_token::*;

#[test]
fn test_nan_probability_rejected_on_encode() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_probability_of_rejection(f64::NAN, vec![1, 2, 3], None);

    assert!(encode_token(&token, &algorithm).is_err());
}

#[test]
fn test_negative_zero_geo_lat_rejected_on_encode() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let mut token = CatToken::new().with_issuer("test");
    token.cat.catgeocoord = Some(vec![GeoCoordinate::new(-0.0_f64, 10.0, 0)]);

    assert!(encode_token(&token, &algorithm).is_err());
}

#[test]
fn test_negative_zero_geo_lon_rejected_on_encode() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let mut token = CatToken::new().with_issuer("test");
    token.cat.catgeocoord = Some(vec![GeoCoordinate::new(10.0, -0.0_f64, 0)]);

    assert!(encode_token(&token, &algorithm).is_err());
}

#[test]
fn test_nan_altitude_rejected_on_encode() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let mut token = CatToken::new().with_issuer("test");
    token.cat.catgeoalt = Some(GeoAltitude::new(f64::NAN, 10.0));

    assert!(encode_token(&token, &algorithm).is_err());
}

#[test]
fn test_negative_zero_deviation_rejected_on_encode() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let mut token = CatToken::new().with_issuer("test");
    token.cat.catgeoalt = Some(GeoAltitude::new(100.0, -0.0_f64));

    assert!(encode_token(&token, &algorithm).is_err());
}

#[test]
fn test_valid_floats_accepted() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_geo_coordinate(0.0, 0.0, 100)
        .with_probability_of_rejection(0.5, vec![1], None);

    assert!(encode_token(&token, &algorithm).is_ok());
}

#[test]
fn test_positive_zero_is_valid() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_geo_coordinate(0.0, 0.0, 0);

    assert!(encode_token(&token, &algorithm).is_ok());
}
