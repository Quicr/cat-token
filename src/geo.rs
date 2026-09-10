// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
use std::net::IpAddr;

/// Optional request-side geographic context integrators may resolve from
/// peer IP or transport metadata. The core validator does not consume
/// this type — it is exposed as a shape callers can use when building
/// their own geo-enforcement layer on top of the token's claims.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RequestLocation {
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub country_code: Option<String>,
    pub subdivision_code: Option<String>,
    pub geohash: Option<String>,
    pub ip_address: Option<IpAddr>,
}

impl RequestLocation {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Trait for pluggable geo-IP resolvers. Callers implement this to
/// hydrate a [`RequestLocation`] from a peer IP when their downstream
/// authorization logic needs country/subdivision context beyond what
/// the token asserts.
pub trait GeoLocationProvider: Send + Sync {
    fn resolve_ip(&self, ip: &IpAddr) -> Result<RequestLocation, CatError>;
}
