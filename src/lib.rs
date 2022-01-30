#[macro_use]
extern crate lazy_static;

pub(crate) mod validators;

use serde::{Deserialize, Serialize};
use std::{fs::read_to_string, io::Result, path::Path};
use validators::{crypto, internet, network, system};

/// All different types of artifacts that which can be found in a given string
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Artifacts {
    /// All found URLs in the given string
    pub urls: Option<Vec<String>>,
    /// All found Domains in the given string
    pub domains: Option<Vec<String>>,
    /// All found Email Addresses in the given string
    pub emails: Option<Vec<String>>,
    /// All found IP Addresses in the given string
    pub ip_address: Option<Vec<String>>,
    /// All found Crypto Addresses in the given string
    pub crypto: Option<Vec<String>>,
    /// All found Registry Keys in the given string
    pub registry_keys: Option<Vec<String>>,
    /// All found SQL Statements in the given string
    pub sql: Option<Vec<String>>,
}

pub fn from_file<P: AsRef<Path>>(file: P) -> Result<Option<Artifacts>> {
    //! Extracts Indicators from a given file
    //!
    //! ## Example Usage
    //! ```rust
    //! use ioc_extract::from_file;
    //!
    //! let f = "data/sample.txt";
    //! println!("{:?}", from_file(f));
    //! ```
    let f = read_to_string(file)?;
    Ok(from_str(&f))
}

pub fn from_str(s: &str) -> Option<Artifacts> {
    //! Extracts Indicators from a given string
    //!
    //! ## Example Usage
    //! ```rust
    //! use ioc_extract::from_str;
    //!
    //! let x = "this is an IP address: 192.168.2.11";
    //! println!("{:?}", x);
    //! ```
    let mut urls = vec![];
    let mut domains = vec![];
    let mut emails = vec![];
    let mut ip_address = vec![];
    let mut crypto_address = vec![];
    let mut registry = vec![];
    let mut sql = vec![];

    // Create a default Indicator object
    let mut iocs = Artifacts::default();

    // check for registry keys & sql queries by breaking only newlines
    // let sr = s.split('\n').collect::<Vec<&str>>();
    for x in s.split('\n').collect::<Vec<&str>>() {
        if system::is_registry_key(x) {
            registry.push(x.to_string())
        } else if system::is_sql(x) {
            sql.push(x.to_string())
        }
    }

    // check for the rest by breaking newlines, whitespace, tabs, etc...
    // let s = s.split_whitespace().collect::<Vec<&str>>();
    for x in s.split_whitespace().collect::<Vec<&str>>() {
        if network::is_ipv_any(x) || network::is_ip_cidr_any(x) {
            ip_address.push(x.to_string())
        } else if crypto::is_cryptocurrency_any(x) {
            crypto_address.push(x.to_string())
        } else if internet::is_domain(x) {
            domains.push(x.to_string())
        } else if internet::is_url(x) {
            urls.push(x.to_string())
        } else if internet::is_email(x, None) {
            emails.push(x.to_string())
        }
    }

    if urls.is_empty()
        && domains.is_empty()
        && emails.is_empty()
        && ip_address.is_empty()
        && crypto_address.is_empty()
        && registry.is_empty()
        && sql.is_empty()
    {
        return None;
    }

    if !urls.is_empty() {
        urls.sort();
        urls.dedup();
        iocs.urls = Some(urls);
    }
    if !domains.is_empty() {
        domains.sort();
        domains.dedup();
        iocs.domains = Some(domains);
    }
    if !emails.is_empty() {
        emails.sort();
        emails.dedup();
        iocs.emails = Some(emails);
    }
    if !ip_address.is_empty() {
        ip_address.sort();
        ip_address.dedup();
        iocs.ip_address = Some(ip_address);
    }
    if !crypto_address.is_empty() {
        crypto_address.sort();
        crypto_address.dedup();
        iocs.crypto = Some(crypto_address);
    }
    if !registry.is_empty() {
        registry.sort();
        registry.dedup();
        iocs.registry_keys = Some(registry);
    }
    if !sql.is_empty() {
        sql.sort();
        sql.dedup();
        iocs.sql = Some(sql);
    }

    // return the result object
    Some(iocs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ip() {
        let x = "there are ips in this test\n192.168.21.21 and ::ffff:127.0.0.1\nthe cidrs are:\n2001:0DB8:1234::/48 and \n10.0.0.0/33";
        let ioc = from_str(x);
        assert!(ioc.is_some());
        let ips = ioc.unwrap().ip_address;
        assert!(ips.is_some())
    }
}
