use b579_core::error::{ArwahError, ArwahResult};
use maxminddb::{geoip2, Reader};
use std::{net::IpAddr, path::Path, sync::Arc};

/// GeoIP lookup backed by MaxMind `.mmdb` database files.
///
/// Wraps the reader in `Arc` so multiple tasks can share one open database.
#[derive(Clone)]
pub struct GeoResolver {
    country_db: Option<Arc<Reader<Vec<u8>>>>,
    asn_db: Option<Arc<Reader<Vec<u8>>>>,
}

impl GeoResolver {
    pub fn new(
        country_path: Option<&Path>,
        asn_path: Option<&Path>,
    ) -> ArwahResult<Self> {
        let country_db = country_path
            .map(|p| Reader::open_readfile(p).map(|r| Arc::new(r)))
            .transpose()
            .map_err(|e| ArwahError::GeoLookup(e.to_string()))?;

        let asn_db = asn_path
            .map(|p| Reader::open_readfile(p).map(|r| Arc::new(r)))
            .transpose()
            .map_err(|e| ArwahError::GeoLookup(e.to_string()))?;

        Ok(Self { country_db, asn_db })
    }

    /// Returns the ISO-3166 country code for `ip`, if available.
    pub fn country_code(&self, ip: IpAddr) -> Option<String> {
        let db = self.country_db.as_ref()?;
        let record: geoip2::Country = db.lookup(ip).ok()?;
        record.country?.iso_code.map(str::to_owned)
    }

    /// Returns the ASN organisation name for `ip`, if available.
    pub fn asn_org(&self, ip: IpAddr) -> Option<String> {
        let db = self.asn_db.as_ref()?;
        let record: geoip2::Asn = db.lookup(ip).ok()?;
        record.autonomous_system_organization.map(str::to_owned)
    }
}
