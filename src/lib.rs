#[macro_use]
extern crate lazy_static;

pub(crate) mod validators;

use serde::{Deserialize, Serialize};
use std::{fs::read_to_string, io::Result, path::Path, sync::{Arc, Mutex}};
use validators::{crypto, internet, network};
use rayon::prelude::*;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Indicators {
    pub urls: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
    pub emails: Option<Vec<String>>,
    pub ip_address: Option<Vec<String>>,
    pub crypto: Option<Vec<String>>,
    pub registry: Option<Vec<String>>,
}

pub fn extract_from_file<P: AsRef<Path>>(file: P) -> Result<Option<Indicators>> {
    //! Extracts Indicators from a given file
    //!
    //! ## Example Usage
    //! ```rust
    //! use ioc_extract::extract_from_file;
    //!
    //! let f = "assets/sample.txt";
    //! println!("{:?}", extract_from_file(f));
    //! ```
    let f = read_to_string(file)?;
    Ok(extract(&f))
}

pub fn extract(s: &str) -> Option<Indicators> {
    //! Extracts Indicators from a given string
    //!
    //! ## Example Usage
    //! ```rust
    //! use ioc_extract::extract;
    //!
    //! let x = "this is an IP address: 192.168.2.11";
    //! println!("{:?}", x);
    //! ```
    let urls = Arc::new(Mutex::new(vec![]));
    let domains = Arc::new(Mutex::new(vec![]));
    let emails = Arc::new(Mutex::new(vec![]));
    let ip_address = Arc::new(Mutex::new(vec![]));
    let crypto_address = Arc::new(Mutex::new(vec![]));
    let mut _registry = vec![];

    // Create a default Indicator object
    let mut iocs = Indicators::default();

    let all_strings = s.split_whitespace().collect::<Vec<&str>>();
    all_strings
        .into_par_iter()
        .for_each(|line| {
            if network::is_ipv_any(line) || network::is_ip_cidr_any(line) {
                ip_address
                    .lock()
                    .expect("poisoned lock")
                    .push(line.to_string());
            } else if crypto::is_cryptocurrency_any(line) && crypto::which_cryptocurrency(line).is_some() {
                crypto_address
                    .lock()
                    .expect("poisoned lock")
                    .push(line.to_string());
            } else if internet::is_domain(line) {
                domains
                    .lock()
                    .expect("poisoned lock")
                    .push(line.to_string());
            } else if internet::is_url(line) {
                urls.lock().expect("poisoned lock").push(line.to_string());
            } else if internet::is_email(line, None) {
                emails.lock().expect("poisoned lock").push(line.to_string());
            }
        });

    let mut urls = urls.lock().expect("lock poisoned").to_vec();
    let mut domains = domains.lock().expect("lock poisoned").to_vec();
    let mut emails = emails.lock().expect("lock poisoned").to_vec();
    let mut ip_address = ip_address.lock().expect("lock poisoned").to_vec();
    let mut crypto_address = crypto_address.lock().expect("lock poisoned").to_vec();

    if urls.is_empty()
        && domains.is_empty()
        && emails.is_empty()
        && ip_address.is_empty()
        && crypto_address.is_empty()
        && _registry.is_empty()
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
    if !_registry.is_empty() {
        _registry.sort();
        _registry.dedup();
        iocs.registry = Some(_registry);
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
        let ioc = extract(x);
        assert!(ioc.is_some());
        println!("{:?}", ioc);
        let ips = ioc.unwrap().ip_address;
        println!("{:?}", ips);
        assert!(ips.is_some())
    }
}
