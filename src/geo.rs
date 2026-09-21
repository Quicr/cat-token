// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Request-side geographic context types.
//!
//! Optional shapes integrators can use to build geo-enforcement on top of a
//! token's geo claims. The core validator does not consume these types.

use crate::CatError;
use std::net::IpAddr;

/// Optional request-side geographic context integrators may resolve from
/// peer IP or transport metadata. The core validator does not consume
/// this type — it is exposed as a shape callers can use when building
/// their own geo-enforcement layer on top of the token's claims.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RequestLocation {
    /// Latitude in decimal degrees.
    pub latitude: Option<f64>,
    /// Longitude in decimal degrees.
    pub longitude: Option<f64>,
    /// ISO 3166-1 country code.
    pub country_code: Option<String>,
    /// ISO 3166-2 subdivision code.
    pub subdivision_code: Option<String>,
    /// Geohash string for the location.
    pub geohash: Option<String>,
    /// Peer IP address the location was resolved from.
    pub ip_address: Option<IpAddr>,
}

impl RequestLocation {
    /// Creates an empty request location with all fields unset.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Trait for pluggable geo-IP resolvers. Callers implement this to
/// hydrate a [`RequestLocation`] from a peer IP when their downstream
/// authorization logic needs country/subdivision context beyond what
/// the token asserts.
pub trait GeoLocationProvider: Send + Sync {
    /// Resolves a [`RequestLocation`] from the given peer IP address.
    fn resolve_ip(&self, ip: &IpAddr) -> Result<RequestLocation, CatError>;
}
