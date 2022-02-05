#[macro_use]
extern crate lazy_static;

mod validators;
mod worker;

use serde::{Deserialize, Serialize};
use std::{fs::read_to_string, io::Result, path::Path, thread::spawn};

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
    /// All found Regular Expressions in the given string
    pub regexes: Option<Vec<String>>,
    /// All found File Paths in the given string
    pub file_paths: Option<Vec<String>>,
}

impl Artifacts {
    pub fn from_file<P: AsRef<Path>>(file: P) -> Result<Option<Self>> {
        //! Extracts Indicators from a given file
        //!
        //! ## Example Usage
        //! ```rust
        //! use ioc_extract::Artifacts;
        //!
        //! let f = "data/sample.txt";
        //! println!("{:?}", Artifacts::from_file(f));
        //! ```
        let f = read_to_string(file)?;
        Ok(Self::from_str(&f))
    }

    pub fn from_str(s: &str) -> Option<Self> {
        //! Extracts Indicators from a given string
        //!
        //! ## Example Usage
        //! ```rust
        //! use ioc_extract::Artifacts;
        //!
        //! let x = "this is an IP address: 192.168.2.11";
        //! println!("{:?}", Artifacts::from_str(x));
        //! ```
        let s1 = s.to_string();
        let s2 = s.to_string();

        let thread_handle1 = spawn(move || worker::by_newline(s1));
        let thread_handle2 = spawn(move || worker::by_whitespace(s2));

        let newline_res = thread_handle1.join().unwrap();
        let whitespace_res = thread_handle2.join().unwrap();

        if newline_res.file_paths.is_none()
            && newline_res.registry_keys.is_none()
            && newline_res.sql.is_none()
            && whitespace_res.regexes.is_none()
            && whitespace_res.crypto.is_none()
            && whitespace_res.emails.is_none()
            && whitespace_res.domains.is_none()
            && whitespace_res.ip_address.is_none()
            && whitespace_res.urls.is_none()
        {
            return None;
        }

        // return the result object
        Some(Artifacts {
            urls: whitespace_res.urls,
            domains: whitespace_res.domains,
            emails: whitespace_res.emails,
            ip_address: whitespace_res.ip_address,
            crypto: whitespace_res.crypto,
            registry_keys: newline_res.registry_keys,
            sql: newline_res.sql,
            regexes: whitespace_res.regexes,
            file_paths: newline_res.file_paths,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ip() {
        let x = "there are ips in this test\n192.168.21.21 and ::ffff:127.0.0.1\nthe cidrs are:\n2001:0DB8:1234::/48 and \n10.0.0.0/33";
        let ioc = Artifacts::from_str(x);
        assert!(ioc.is_some());
        let ips = ioc.unwrap().ip_address;
        assert!(ips.is_some())
    }
}
