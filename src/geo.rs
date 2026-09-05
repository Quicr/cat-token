// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
use crate::claims::{CatToken, NetworkIdentifier};
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub struct RequestLocation {
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub country_code: Option<String>,
    pub subdivision_code: Option<String>,
    pub geohash: Option<String>,
    pub ip_address: Option<IpAddr>,
}

pub trait GeoLocationProvider: Send + Sync {
    fn resolve_ip(&self, ip: &IpAddr) -> Result<RequestLocation, CatError>;
}

pub fn validate_geographic_enforcement(
    token: &CatToken,
    location: &RequestLocation,
) -> Result<(), CatError> {
    if let Some(ref codes) = token.cat.catgeoiso3166 {
        validate_iso3166(codes, location)?;
    }

    if let Some(ref coords) = token.cat.catgeocoord {
        validate_coordinates(coords, location)?;
    }

    if let Some(ref geohashes) = token.cat.geohash {
        validate_geohash(geohashes, location)?;
    }

    if let Some(ref nips) = token.cat.catnip {
        validate_ip_network(nips, location)?;
    }

    Ok(())
}

fn validate_iso3166(allowed_codes: &[String], location: &RequestLocation) -> Result<(), CatError> {
    let country_match = location
        .country_code
        .as_ref()
        .is_some_and(|cc| allowed_codes.iter().any(|allowed| allowed == cc));

    let subdivision_match = location
        .subdivision_code
        .as_ref()
        .is_some_and(|sc| allowed_codes.iter().any(|allowed| allowed == sc));

    if country_match || subdivision_match {
        return Ok(());
    }

    Err(CatError::GeographicValidationFailed(
        "request location does not match any allowed ISO 3166 codes".to_string(),
    ))
}

fn validate_coordinates(
    zones: &[crate::claims::GeoCoordinate],
    location: &RequestLocation,
) -> Result<(), CatError> {
    let (req_lat, req_lon) = match (location.latitude, location.longitude) {
        (Some(lat), Some(lon)) => (lat, lon),
        _ => {
            return Err(CatError::GeographicValidationFailed(
                "request has no coordinates but token requires catgeocoord check".to_string(),
            ));
        }
    };

    for zone in zones {
        let distance = haversine_distance_meters(req_lat, req_lon, zone.lat, zone.lon);
        if distance <= zone.radius as f64 {
            return Ok(());
        }
    }

    Err(CatError::GeographicValidationFailed(
        "request location outside all allowed geographic zones".to_string(),
    ))
}

fn validate_geohash(allowed: &[String], location: &RequestLocation) -> Result<(), CatError> {
    let req_geohash = location.geohash.as_ref().ok_or_else(|| {
        CatError::GeographicValidationFailed(
            "request has no geohash but token requires geohash check".to_string(),
        )
    })?;

    for allowed_gh in allowed {
        if req_geohash.starts_with(allowed_gh.as_str()) {
            return Ok(());
        }
    }

    Err(CatError::GeographicValidationFailed(
        "request geohash does not match any allowed geohash prefixes".to_string(),
    ))
}

fn validate_ip_network(
    nips: &[NetworkIdentifier],
    location: &RequestLocation,
) -> Result<(), CatError> {
    let req_ip = location.ip_address.ok_or_else(|| {
        CatError::GeographicValidationFailed(
            "request has no IP address but token requires catnip check".to_string(),
        )
    })?;

    for nip in nips {
        match nip {
            NetworkIdentifier::IpAddress(allowed) => {
                if req_ip == *allowed {
                    return Ok(());
                }
            }
            NetworkIdentifier::IpPrefix(network, prefix_len) => {
                if ip_in_prefix(req_ip, *network, *prefix_len) {
                    return Ok(());
                }
            }
            NetworkIdentifier::Asn(_) | NetworkIdentifier::AsnRange(_, _) => {}
        }
    }

    Err(CatError::GeographicValidationFailed(
        "request IP not within any allowed network".to_string(),
    ))
}

fn haversine_distance_meters(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_000.0;

    let lat1_r = lat1.to_radians();
    let lat2_r = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();

    let a = (dlat / 2.0).sin().powi(2) + lat1_r.cos() * lat2_r.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();

    EARTH_RADIUS_M * c
}

fn ip_in_prefix(ip: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix_len);
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine_same_point() {
        let d = haversine_distance_meters(40.7128, -74.0060, 40.7128, -74.0060);
        assert!(d < 0.01);
    }

    #[test]
    fn test_haversine_known_distance() {
        // NYC to LA ~ 3,944 km
        let d = haversine_distance_meters(40.7128, -74.0060, 34.0522, -118.2437);
        assert!((d - 3_944_000.0).abs() < 50_000.0);
    }

    #[test]
    fn test_ip_in_prefix_v4() {
        let net: IpAddr = "10.0.0.0".parse().unwrap();
        let ip_in: IpAddr = "10.0.1.5".parse().unwrap();
        let ip_out: IpAddr = "11.0.0.1".parse().unwrap();

        assert!(ip_in_prefix(ip_in, net, 8));
        assert!(!ip_in_prefix(ip_out, net, 8));
    }

    #[test]
    fn test_ip_in_prefix_v6() {
        let net: IpAddr = "2001:db8::".parse().unwrap();
        let ip_in: IpAddr = "2001:db8::1".parse().unwrap();
        let ip_out: IpAddr = "2001:db9::1".parse().unwrap();

        assert!(ip_in_prefix(ip_in, net, 32));
        assert!(!ip_in_prefix(ip_out, net, 32));
    }

    #[test]
    fn test_ip_prefix_zero() {
        let net: IpAddr = "0.0.0.0".parse().unwrap();
        let any_ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(ip_in_prefix(any_ip, net, 0));
    }
}
