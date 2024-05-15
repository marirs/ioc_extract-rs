use crate::validators::{
    crypto::{self, which_cryptocurrency},
    internet, network, system,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct NewlineResult {
    pub registry_keys: Option<Vec<String>>,
    pub sql: Option<Vec<String>>,
    pub file_paths: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct WhitespaceResult {
    pub urls: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
    pub emails: Option<Vec<String>>,
    pub ip_address: Option<Vec<String>>,
    pub crypto: Option<Vec<String>>,
    pub regexes: Option<Vec<String>>,
}

pub fn by_newline(s: String) -> NewlineResult {
    let mut registry = vec![];
    let mut sql = vec![];
    let mut file_paths = vec![];

    // check for registry keys & sql queries by breaking only newlines
    for x in s.split('\n').collect::<Vec<&str>>() {
        let x = x.trim();
        if system::is_registry_key(x) {
            registry.push(x.to_string())
        } else if system::is_sql(x) {
            sql.push(x.to_string())
        } else if system::is_file_path(x) {
            file_paths.push(x.to_string())
        }
    }

    NewlineResult {
        registry_keys: if !registry.is_empty() {
            registry.sort();
            registry.dedup();
            Some(registry)
        } else {
            None
        },
        sql: if !sql.is_empty() {
            sql.sort();
            sql.dedup();
            Some(sql)
        } else {
            None
        },
        file_paths: if !file_paths.is_empty() {
            file_paths.sort();
            file_paths.dedup();
            Some(file_paths)
        } else {
            None
        },
    }
}

pub fn by_whitespace(s: String) -> WhitespaceResult {
    let mut urls = vec![];
    let mut domains = vec![];
    let mut emails = vec![];
    let mut ip_address = vec![];
    let mut crypto_address = vec![];
    let mut regexes = vec![];

    // check for the rest by breaking newlines, whitespace, tabs, etc...
    for x in s.split_whitespace().collect::<Vec<&str>>() {
        let x = x.trim();
        if network::is_ipv_any(x) || network::is_ip_cidr_any(x) {
            ip_address.push(x.to_string())
        } else if crypto::is_cryptocurrency_any(x) {
            crypto_address.push(format!("{} - {}", x, which_cryptocurrency(x).unwrap()))
        } else if internet::is_domain(x) {
            domains.push(x.to_string())
        } else if let Some(url) = internet::get_url(x) {
            urls.push(url)
        } else if internet::is_email(x, None) {
            emails.push(x.to_string())
        } else if system::is_regex(x) {
            regexes.push(x.to_string())
        }
    }

    WhitespaceResult {
        urls: if !urls.is_empty() {
            urls.sort();
            urls.dedup();
            Some(urls)
        } else {
            None
        },
        domains: if !domains.is_empty() {
            domains.sort();
            domains.dedup();
            Some(domains)
        } else {
            None
        },
        emails: if !emails.is_empty() {
            emails.sort();
            emails.dedup();
            Some(emails)
        } else {
            None
        },
        ip_address: if !ip_address.is_empty() {
            ip_address.sort();
            ip_address.dedup();
            Some(ip_address)
        } else {
            None
        },
        crypto: if !crypto_address.is_empty() {
            crypto_address.sort();
            crypto_address.dedup();
            Some(crypto_address)
        } else {
            None
        },
        regexes: if !regexes.is_empty() {
            regexes.sort();
            regexes.dedup();
            Some(regexes)
        } else {
            None
        },
    }
}
