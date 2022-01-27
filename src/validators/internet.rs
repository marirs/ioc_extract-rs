use idna::domain_to_ascii;
use regex::Regex;

lazy_static! {
    static ref DOMAIN: Regex = Regex::new(
        &[
            r"(?i)^(?:[a-zA-Z0-9]",                     // First character of the domain
            r"(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)",  // Sub domain + hostname
            r"+[A-Za-z0-9][A-Za-z0-9-_]{0,61}",         // First 61 characters of the gTLD
            r"[A-Za-z]$",                               // Last character of the gTLD
        ].join("")
    ).unwrap();
    static ref DOMAIN_WHITELIST: Vec<&'static str> = vec!["localhost"];
    static ref DOMAINS_EXT: Vec<String> = tld_download::download(false).unwrap_or_default();
    static ref EMAIL: Regex = Regex::new(r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z0-9\-]*$").unwrap();
    static ref EMAIL_DOMAIN: Regex = Regex::new(
        &[
            // ignore case
            r"(?i)",
            // domain
            r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+",
            r"(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?$)",
            // literal form, ipv4 address (SMTP 4.1.3)
            r"|^\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)",
            r"(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\]$",
        ].join("")
    ).unwrap();
    static ref IP_MIDDLE_OCTET: &'static str = r"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5]))";
    static ref IP_LAST_OCTET: &'static str = r"(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))";
    static ref URL: Regex = Regex::new(
        &[
            r"(?i)^",
            // protocol identifier
            r"(?:(?:https?|ftp)://)",
            // user:pass authentication
            r"(?:[-a-z\u00a1-\uffff0-9._~%!$&'()*+,;=:]+",
            r"(?::[-a-z0-9._~%!$&'()*+,;=:]*)?@)?",
            r"(?:",
            r"(?P<private_ip>",
            // IP address exclusion
            // private & local networks
            format!(r"(?:(?:10|127){}{}{})|", *IP_MIDDLE_OCTET, r"{2}", *IP_LAST_OCTET).as_str(),
            format!(r"(?:(?:169\.254|192\.168){}{})|", *IP_MIDDLE_OCTET, *IP_LAST_OCTET).as_str(),
            format!(r"(?:172\.(?:1[6-9]|2\d|3[0-1]){}{}))", *IP_MIDDLE_OCTET, *IP_LAST_OCTET).as_str(),
            r"|",
            // private & local hosts
            r"(?P<private_host>",
            r"(?:localhost))",
            r"|",
            // IP address dotted notation octets
            // excludes loopback network 0.0.0.0
            // excludes reserved space >= 224.0.0.0
            // excludes network & broadcast addresses
            // (first & last IP address of each class)
            r"(?P<public_ip>",
            r"(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])",
            format!("{}{}", *IP_MIDDLE_OCTET, r"{2}").as_str(),
            format!("{})", *IP_LAST_OCTET).as_str(),
            r"|",
            // IPv6 RegEx from https://stackoverflow.com/a/17871737
            r"\[(",
            // 1:2:3:4:5:6:7:8
            r"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|",
            // 1::                              1:2:3:4:5:6:7::
            r"([0-9a-fA-F]{1,4}:){1,7}:|",
            // 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
            r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|",
            // 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
            r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|",
            // 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
            r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|",
            // 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
            r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|",
            // 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
            r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|",
            // 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
            r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|",
            // ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
            r":((:[0-9a-fA-F]{1,4}){1,7}|:)|",
            // fe80::7:8%eth0   fe80::7:8%1
            // (link-local IPv6 addresses with zone index)
            r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|",
            r"::(ffff(:0{1,4}){0,1}:){0,1}",
            r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}",
            // ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255
            // (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
            r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|",
            r"([0-9a-fA-F]{1,4}:){1,4}:",
            r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}",
            // 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33
            // (IPv4-Embedded IPv6 Address)
            r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])",
            r")\]|",
            // host name
            r"(?:(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)",
            // domain name
            r"(?:\.(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)*",
            // TLD identifier
            r"(?:\.(?:[a-z\u00a1-\uffff]{2,}))",
            r")",
            // port number
            r"(?::\d{2,5})?",
            // resource path
            r"(?:/[-a-z\u00a1-\uffff0-9._~%!$&'()*+,;=:@/]*)?",
            // query string
            r"(?:\?\S*)?",
            // fragment
            r"(?:#\S*)?",
            r"$",
        ].join("")
    ).unwrap();
}

fn is_tld_valid(domain: &str) -> bool {
    //! Checks to see if a Given Domain contains a valid tld like
    //! NO numbers or special characters or file extensions.
    let parts: Vec<&str> = domain.splitn(2, '.').collect();
    if parts.len() > 1 {
        // Check to see if TLD contains numbers
        // Before IDN conversion; tld will not have numbers
        let tld = parts[1].to_lowercase();
        if tld
            .chars()
            .map(|c| (c.is_alphabetic() || c == '.'))
            .any(|x| !x)
        {
            // make sure that we dont
            // have numbers in the tld
            return false;
        }
    }
    // TLD not present
    // and/or tld is valid
    true
}

pub fn is_email(value: &str, whitelist: Option<Vec<&str>>) -> bool {
    //! Check if the given value is an Email Address.
    if value.is_empty() || !value.contains('@') {
        return false;
    }

    let whitelist = match whitelist {
        Some(x) => x,
        None => DOMAIN_WHITELIST.to_vec(),
    };
    let parts: Vec<&str> = value.rsplitn(2, '@').collect();
    let user_part = parts[1];
    let domain_part = parts[0];

    if !is_tld_valid(domain_part) {
        return false;
    }
    // Convert to IDN
    let user_part = match domain_to_ascii(user_part) {
        Ok(x) => x,
        Err(_) => return false,
    };
    if user_part.len() > 64 {
        return false;
    }
    // Convert to IDN
    let domain_part = match domain_to_ascii(domain_part) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let value = format!("{}@{}", user_part, domain_part);

    EMAIL.is_match(&value) && EMAIL_DOMAIN.is_match(&domain_part)
        || whitelist.contains(&domain_part.as_str())
}

pub fn is_domain(value: &str) -> bool {
    //! Check if the given value is a Domain Name.
    let x = match domain_to_ascii(value) {
        Ok(x) => x,
        Err(_) => return false,
    };

    if DOMAIN.is_match(&x) && DOMAINS_EXT.iter().any(|suffix| x.ends_with(suffix)) {
        return true;
    }

    false
}

pub fn is_url(value: &str) -> bool {
    //! Check if the given value is a URL.
    URL.is_match(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tld_valid() {
        // Valid
        assert!(is_tld_valid("example.com"));
        assert!(is_tld_valid("example.co.uk"));
        assert!(is_tld_valid("example.io"));
        assert!(is_tld_valid("清华大学.cn"));

        // Invalid
        assert!(!is_tld_valid("example.c1om"));
        assert!(!is_tld_valid("example.co9.uk"));
        assert!(!is_tld_valid("example.i1o"));
        assert!(!is_tld_valid("清华大学.cn9"));
    }

    #[test]
    fn test_is_email() {
        // Valid
        assert!(is_email("doe_john@example.com", None));
        assert!(is_email("doe-john@example.com", None));
        assert!(is_email("doe.john@example.com", None));
        assert!(is_email("johndoe@example.com", None));
        assert!(is_email("doe.john1940@example.com", None));
        assert!(is_email("johndoe@example.co.uk", None));
        assert!(is_email("johndoe@транспорт.com", None));
        assert!(is_email("johndoe@清华大学.cn", None));
        assert!(is_email("Маниш@Ашок.Индия", None));
        assert!(is_email("अ@अशोका.भारत", None));
        assert!(is_email("johndoe@localhost", None));

        // Invalid
        assert!(!is_email("johndoe@nonsupporteddomain", None));
        assert!(!is_email("johndoe@example.c9om", None));
        assert!(!is_email("johndoe@example.co9.uk", None));
        assert!(!is_email("johndoe@example.co1.u9k", None));
        assert!(!is_email("johndoe@清华大学.cn9", None));
        assert!(!is_email("john doe@example.com", None));
    }

    #[test]
    fn test_is_domain() {
        // Valid
        assert!(is_domain("example.com"));
        assert!(is_domain("www.example.co.uk"));
        assert!(is_domain("www.v2.example.co.uk"));
        assert!(is_domain("清华大学.cn"));
        assert!(is_domain("अशोका.भारत"));

        // Invalid
        assert!(!is_domain("@example.com"));
        assert!(!is_domain("http://www.транспорт.com"));
        assert!(!is_domain("https://www.example.com"));
        assert!(!is_domain("example.com invalid"));
        assert!(!is_domain("kernel32.DLL"));
    }

    #[test]
    fn test_is_url() {
        // Valid
        assert!(is_url("https://www.example.com"));
        assert!(is_url("https://example.com"));
        assert!(is_url("https://example.co.uk"));
        assert!(is_url("http://www.example.co.uk"));
        assert!(is_url("https://localhost:8443"));
        assert!(is_url("http://localhost"));
        assert!(is_url("http://清华大学.cn"));

        // Invalid
        assert!(!is_url("abc.com"));
        assert!(!is_url("localhost"));
        assert!(!is_url("localhost:9455"));
    }
}
