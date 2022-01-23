use std::{net::IpAddr, str::FromStr};

pub fn is_ipv4(value: &str) -> bool {
    //! Check to see if a given value corresponds to IPv4 Address.
    let ip = if let Ok(ipaddr) = IpAddr::from_str(value) {
        ipaddr
    } else {
        return false;
    };
    ip.is_ipv4()
}

pub fn is_ipv4_cidr(value: &str) -> bool {
    //! Check to see if a given IPv4 Address with CIDR is valid.
    let splitted_groups: Vec<&str> = value.splitn(2, '/').collect();
    let prefix;
    let suffix;
    if splitted_groups.len() > 1 {
        prefix = splitted_groups[0];
        suffix = splitted_groups[1];
    } else {
        return false;
    }

    let nsuffix: u32 = match suffix.parse() {
        Ok(x) => x,
        Err(_) => return false,
    };

    if nsuffix > 32 {
        return false;
    }

    if !is_ipv4(prefix) {
        return false;
    }

    true
}

pub fn is_ipv6(value: &str) -> bool {
    //! Check to see if a given value corresponds to IPv6 Address.
    let ip = if let Ok(ipaddr) = IpAddr::from_str(value) {
        ipaddr
    } else {
        return false;
    };
    ip.is_ipv6()
}

pub fn is_ipv6_cidr(value: &str) -> bool {
    //! Check to see if a given IPv6 Address with CIDR is valid.
    let splitted_groups: Vec<&str> = value.splitn(2, '/').collect();
    let prefix;
    let suffix;
    if splitted_groups.len() > 1 {
        prefix = splitted_groups[0];
        suffix = splitted_groups[1];
    } else {
        return false;
    }

    let nsuffix: u32 = match suffix.parse() {
        Ok(x) => x,
        Err(_) => return false,
    };

    if nsuffix > 128 {
        return false;
    }

    if !is_ipv6(prefix) {
        return false;
    }

    true
}

pub fn is_ip_loopback(value: &str) -> bool {
    //! Check to see if a given value corresponds to Local/loopback IP Address.
    let ip = if let Ok(ipaddr) = IpAddr::from_str(value) {
        ipaddr
    } else {
        return false;
    };
    ip.is_loopback()
}

pub fn is_ipv_any(value: &str) -> bool {
    //! Check to see if a given value corresponds to any IP Address.
    if is_ipv4(value) || is_ipv6(value) {
        return true;
    }
    false
}

pub fn is_ip_cidr_any(value: &str) -> bool {
    //! Check to see if a given value corresponds to any IP CIDR.
    if is_ipv4_cidr(value) || is_ipv6_cidr(value) {
        return true;
    }
    false
}

pub fn which_ipv(value: &str) -> Option<&str> {
    //! Check to see if a given value corresponds to IP Address & return its IP version.
    if is_ipv4(value) {
        return Some("IPv4");
    } else if is_ipv6(value) {
        return Some("IPv6");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ipv4() {
        assert!(is_ipv4("10.10.10.1"));
        assert!(is_ipv4("100.128.10.132"));
        assert!(!is_ipv4("12.110.105.256"));
        assert!(!is_ipv4("10.2.13"));
        assert!(!is_ipv4("256.10.10.1000"));
        assert!(is_ipv4("100.17.5.119"));
        assert!(is_ipv4("127.0.0.1"));
    }

    #[test]
    fn test_is_ipv4_cidr() {
        assert!(is_ipv4_cidr("10.0.0.0/8"));
        assert!(is_ipv4_cidr("10.0.0.0/32"));
        assert!(!is_ipv4_cidr("10.0.0.0/33"));
        assert!(!is_ipv4_cidr("270.0.0.1000/24"));
    }

    #[test]
    fn test_is_ipv6() {
        assert!(is_ipv6("2041:0000:140F::875B:131B"));
        assert!(is_ipv6("::ffff:127.0.0.1"));
        assert!(is_ipv6("::ffff:7f00:1"));
        assert!(is_ipv6("::1"));
        assert!(is_ipv6("2041:0:140F::875B:131B"));
        assert!(is_ipv6("2041:0000:140F::875B:131B"));
        assert!(is_ipv6("fcb7:360a:242a:2d0d:392e:bc22:a45:3573"));
        assert!(!is_ipv6("2002:::1234::"));
        assert!(is_ipv6("3b8f:473b:d1a7:ba09:d28c:3cd:7f46:c95e"));
        assert!(is_ipv6("0000:0000:0000:0000:0000:FFFF:2BE0:9E74"));
        assert!(is_ipv6("::ffff:43.224.158.116"));
    }

    #[test]
    fn test_is_ipv6_cidr() {
        assert!(is_ipv6_cidr("2001:0DB8:1234::/48"));
        assert!(is_ipv6_cidr("2001:0DB8:12a4::/128"));
        assert!(!is_ipv6_cidr("2005:0DB8:1234::/130"));
        assert!(!is_ipv6_cidr("2002:::1234::/48"));
    }

    #[test]
    fn test_is_ip_loopback() {
        assert!(is_ip_loopback("127.0.0.1"));
        assert!(is_ip_loopback("::1"));
        assert!(!is_ip_loopback("10.122.1.130"));
        assert!(!is_ip_loopback("::ffff:7f00:1"));
    }

    #[test]
    fn test_is_ipv_any() {
        // valid
        assert!(is_ipv_any("127.0.0.1"));
        assert!(is_ipv_any("::1"));

        // not valid
        assert!(!is_ipv_any("127.0.0.1.36"));
        assert!(!is_ipv_any("2A00:17C8:50C:0000:0000:0000:0000:00001"));
    }

    #[test]
    fn test_is_ip_cidr_any() {
        // valid
        assert!(is_ip_cidr_any("2001:0DB8:1234::/48"));
        assert!(is_ip_cidr_any("10.0.0.0/8"));

        // not valid
        assert!(!is_ip_cidr_any("2002:::1234::/48"));
        assert!(!is_ip_cidr_any("10.0.0.0/33"));
    }
    #[test]
    fn test_which_ipv() {
        assert_eq!(which_ipv("::1"), Some("IPv6"));
        assert_eq!(which_ipv("127.0.0.1"), Some("IPv4"));
        assert_eq!(which_ipv("2002:::1234::"), None);
    }
}
