// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;
use chrono::Utc;

#[test]
fn test_core_claims() {
    let token = CatToken::new()
        .with_issuer("https://issuer.example.com")
        .with_audience(vec!["audience1".to_string(), "audience2".to_string()])
        .with_expiration(Utc::now() + chrono::Duration::hours(1))
        .with_not_before(Utc::now() - chrono::Duration::minutes(5))
        .with_cwt_id_str("unique-token-id");

    assert_eq!(
        token.core.iss,
        Some("https://issuer.example.com".to_string())
    );
    assert!(
        token
            .core
            .aud
            .as_ref()
            .unwrap()
            .contains(&"audience1".to_string())
    );
    assert!(
        token
            .core
            .aud
            .as_ref()
            .unwrap()
            .contains(&"audience2".to_string())
    );
    assert!(token.core.exp.is_some());
    assert!(token.core.nbf.is_some());
    assert_eq!(token.core.cti, Some(b"unique-token-id".to_vec()));
}

#[test]
fn test_cat_claims() {
    let uri_rules = vec![
        UriMatchRule {
            component: URI_COMPONENT_HOST,
            matches: vec![MatchValue::Exact("api.example.com".to_string())],
        },
    ];
    let token = CatToken::new()
        .with_version(1)
        .with_uri_match_rules(uri_rules.clone())
        .with_replay_protection(cat_token::ReplayProtection::Prohibited)
        .with_geo_coordinate(37.7749, -122.4194, Some(10))
        .with_geohash("9q8yy");

    assert_eq!(token.cat.catv, Some(1));
    assert_eq!(token.cat.catu, Some(uri_rules));
    assert_eq!(token.cat.catreplay, Some(cat_token::ReplayProtection::Prohibited));

    assert!(token.cat.catgeocoord.is_some());
    let coords = token.cat.catgeocoord.unwrap();
    assert_eq!(coords[0].lat, 37.7749);
    assert_eq!(coords[0].lon, -122.4194);
    assert_eq!(coords[0].radius, Some(10));

    assert_eq!(token.cat.geohash, Some("9q8yy".to_string()));
}

#[test]
fn test_informational_claims() {
    let iat = Utc::now();
    let token = CatToken::new()
        .with_subject("user123")
        .with_issued_at(iat)
        .with_interface_data("interface-data");

    assert_eq!(token.informational.sub, Some("user123".to_string()));
    assert_eq!(token.informational.iat, Some(iat.timestamp()));
    assert_eq!(
        token.informational.catifdata,
        Some("interface-data".to_string())
    );
}

#[test]
fn test_dpop_claims() {
    let jkt = b"confirmation-key".to_vec();
    let token = CatToken::new()
        .with_confirmation(jkt.clone())
        .with_dpop_settings(CatDpopSettings::new().with_window(300));

    assert!(token.dpop.cnf.is_some());
    assert_eq!(token.dpop.cnf.as_ref().unwrap().jkt, jkt);
    assert!(token.dpop.catdpop.is_some());
    assert_eq!(token.dpop.catdpop.as_ref().unwrap().window, Some(300));
}

#[test]
fn test_request_claims() {
    let token = CatToken::new()
        .with_interface_claim("interface123")
        .with_request_claim("request456");

    assert_eq!(token.request.catif, Some("interface123".to_string()));
    assert_eq!(token.request.catr, Some("request456".to_string()));
}

#[test]
fn test_uri_match_rules() {
    let rules = vec![
        UriMatchRule {
            component: URI_COMPONENT_SCHEME,
            matches: vec![MatchValue::Exact("https".to_string())],
        },
        UriMatchRule {
            component: URI_COMPONENT_HOST,
            matches: vec![
                MatchValue::Exact("api.example.com".to_string()),
                MatchValue::Suffix(".example.com".to_string()),
            ],
        },
        UriMatchRule {
            component: URI_COMPONENT_PATH,
            matches: vec![
                MatchValue::Prefix("/api/".to_string()),
                MatchValue::Regex(r"^/v[0-9]+/.*$".to_string()),
                MatchValue::Contains("resource".to_string()),
            ],
        },
        UriMatchRule {
            component: URI_COMPONENT_EXTENSION,
            matches: vec![MatchValue::Exact("json".to_string())],
        },
    ];

    let token = CatToken::new().with_uri_match_rules(rules.clone());
    assert_eq!(token.cat.catu, Some(rules));
}

#[test]
fn test_token_builder() {
    let jkt = b"conf-key".to_vec();
    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .audience(vec!["client1".to_string()])
        .expires_at(Utc::now() + chrono::Duration::hours(2))
        .version(1)
        .subject("user456")
        .confirmation(jkt.clone())
        .interface_claim("if789")
        .build();

    assert_eq!(token.core.iss, Some("https://auth.example.com".to_string()));
    assert_eq!(token.cat.catv, Some(1));
    assert_eq!(token.informational.sub, Some("user456".to_string()));
    assert!(token.dpop.cnf.is_some());
    assert_eq!(token.dpop.cnf.as_ref().unwrap().jkt, jkt);
    assert_eq!(token.request.catif, Some("if789".to_string()));
}

#[test]
fn test_geo_coordinate_validation() {
    // Valid coordinates
    let coord1 = GeoCoordinate {
        lat: 45.0,
        lon: 90.0,
        radius: None,
    };
    assert!(coord1.lat.abs() <= 90.0);
    assert!(coord1.lon.abs() <= 180.0);

    // Edge case coordinates
    let coord2 = GeoCoordinate {
        lat: -90.0,
        lon: -180.0,
        radius: Some(5),
    };
    assert!(coord2.lat.abs() <= 90.0);
    assert!(coord2.lon.abs() <= 180.0);

    let coord3 = GeoCoordinate {
        lat: 90.0,
        lon: 180.0,
        radius: Some(1),
    };
    assert!(coord3.lat.abs() <= 90.0);
    assert!(coord3.lon.abs() <= 180.0);
}

#[test]
fn test_claim_constants() {
    // Core claims
    assert_eq!(CLAIM_ISS, 1);
    assert_eq!(CLAIM_AUD, 3);
    assert_eq!(CLAIM_EXP, 4);
    assert_eq!(CLAIM_NBF, 5);
    assert_eq!(CLAIM_CTI, 7);

    // CAT claims
    assert_eq!(CLAIM_CATREPLAY, 308);
    assert_eq!(CLAIM_CATPOR, 309);
    assert_eq!(CLAIM_CATV, 310);
    assert_eq!(CLAIM_CATNIP, 311);
    assert_eq!(CLAIM_CATU, 312);

    // Informational claims
    assert_eq!(CLAIM_SUB, 2);
    assert_eq!(CLAIM_IAT, 6);
    assert_eq!(CLAIM_CATIFDATA, 320);
    assert_eq!(CLAIM_CNF, 8);
    assert_eq!(CLAIM_CATDPOP, 321);
    assert_eq!(CLAIM_CATIF, 322);
    assert_eq!(CLAIM_CATR, 323);
}
