use fancy_regex::Regex;

lazy_static! {
    /// Bitcoin Regex Pattern
    static ref BTC: Regex = Regex::new(r"(?i)^[13][a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59}\b").unwrap();
    /// Bitcoin Cash Regex Pattern
    static ref BCH: Regex = Regex::new(r"(?i)^(((bitcoincash|bchreg|bchtest):)?(?:q|p)[a-z0-9]{41}|[13][a-km-zA-HJ-NP-Z1-9]{33})\b").unwrap();
    /// Ethereum Regex Pattern
    static ref ETH: Regex = Regex::new(r"(?i)^0x[a-fA-F0-9]{40}\b").unwrap();
    /// Litecoin Regex Pattern
    static ref LTC: Regex = Regex::new(r"(?i)^(?:ltc1|[LM])(?=\S*?\d\S*?\b)[a-km-zA-HJ-NP-Z1-9]{26,33}\b").unwrap();
    /// Dodge Coin Regex Pattern
    static ref DODGE: Regex = Regex::new(r"(?i)^D[5-9A-HJ-NP-U][1-9a-km-zA-HJ-NP-Z]{32}\b").unwrap();
    /// Dash Regex Pattern
    static ref DASH: Regex = Regex::new(r"(?i)^X[1-9A-HJ-NP-Za-km-z]{33}\b").unwrap();
    /// Monero Regex Pattern
    static ref XMR: Regex = Regex::new(r"(?i)^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b").unwrap();
    /// Neo Regex Pattern
    static ref NEO: Regex = Regex::new(r"(?i)^A[0-9a-zA-Z]{33}\b").unwrap();
    /// Ripple Regex Pattern
    static ref XRP: Regex = Regex::new(r"(?i)^[rx](?=\S*?\d\S*?\b)[0-9a-zA-Z]{33,47}\b").unwrap();

    /// Incase of Illegal chars for a Crypto Wallet
    static ref ILLEGAL_CHARS: Vec<String> = [
        '.', '!', '%', '*', '$', '#', '@', ')', '(', '^', '`', '~', '|',
        '>', '<', '-', '_', '"', '\\', '}', '{', ':', ';', ',', '/', '?',
    ]
        .iter()
        .map(|c|c.to_string())
        .collect();
}

enum Type {
    Bitcoin,
    BitcoinCash,
    Ethereum,
    Litecoin,
    Dodge,
    Dash,
    Monero,
    Neo,
    Ripple,
}

impl Type {
    fn name<'a>(&self) -> &'a str {
        match *self {
            Type::Bitcoin => "Bitcoin",
            Type::BitcoinCash => "Bitcoin Cash",
            Type::Ethereum => "Ethereum",
            Type::Litecoin => "Litecoin",
            Type::Dodge => "Dodgecoin",
            Type::Dash => "Dash",
            Type::Monero => "Monero",
            Type::Neo => "Neo",
            Type::Ripple => "Ripple",
        }
    }

    fn pattern<'a>(&self) -> &'a Regex {
        match *self {
            Type::Bitcoin => &BTC,
            Type::BitcoinCash => &BCH,
            Type::Ethereum => &ETH,
            Type::Litecoin => &LTC,
            Type::Dodge => &DODGE,
            Type::Dash => &DASH,
            Type::Monero => &XMR,
            Type::Neo => &NEO,
            Type::Ripple => &XRP,
        }
    }

    fn all() -> Vec<Type> {
        vec![
            Type::Bitcoin,
            Type::BitcoinCash,
            Type::Ethereum,
            Type::Litecoin,
            Type::Dodge,
            Type::Dash,
            Type::Monero,
            Type::Neo,
            Type::Ripple,
        ]
    }
}

/// Evaluate CryptoCurrency & Validate
fn validate(value: &str) -> bool {
    // have a min of 15 chars at-least before evaluating
    if value.chars().count() > 15
        && value.chars().any(|c| c.is_ascii_digit())
        && !value.is_empty()
        && !ILLEGAL_CHARS.iter().any(|c| value.contains(c))
    {
        for cryptocurrency in Type::all() {
            if cryptocurrency.pattern().is_match(value).unwrap() {
                return true;
            }
        }
    }
    false
}

pub fn is_bitcoin(value: &str) -> bool {
    //! Check if the given crypto address is Bitcoin.
    validate(value)
}

pub fn is_bitcoin_cash(value: &str) -> bool {
    //! Check if the given crypto address is Bitcoin Cash.
    validate(value)
}

pub fn is_ethereum(value: &str) -> bool {
    //! Check if the given crypto address is Ethereum.
    validate(value)
}

pub fn is_litecoin(value: &str) -> bool {
    //! Check if the given crypto address is Litecoin.
    validate(value)
}

pub fn is_dogecoin(value: &str) -> bool {
    //! Check if the given crypto address is Dodgecoin.
    validate(value)
}

pub fn is_dash(value: &str) -> bool {
    //! Check if the given crypto address is Dash.
    validate(value)
}

pub fn is_monero(value: &str) -> bool {
    //! Check if the given crypto address is Monero.
    validate(value)
}

pub fn is_neo(value: &str) -> bool {
    //! Check if the given crypto address is Neo.
    validate(value)
}

pub fn is_ripple(value: &str) -> bool {
    //! Check if the given crypto address is Ripple.
    validate(value)
}

pub fn is_cryptocurrency_any(value: &str) -> bool {
    //! Check if the given string is a Crypto Currency.
    validate(value)
}

pub fn which_cryptocurrency(value: &str) -> Option<&str> {
    //! Output the Crypto Currency Name given the cryptocurrencty address.
    for cryptocurrency in Type::all() {
        if cryptocurrency.pattern().is_match(value).unwrap_or_default() {
            return Some(cryptocurrency.name());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_which_cryptocurrency() {
        // Bitcoin
        assert_eq!(
            which_cryptocurrency("1GiWxH6PzSSmbdcK72XfGpqhjSb6nae6h9"),
            Some("Bitcoin")
        );
        // Bitcoin Cash
        assert_eq!(
            which_cryptocurrency("qppjlghjlwg6tgxv7ffhvs43rlul0kpp4c0shk4dr6"),
            Some("Bitcoin Cash")
        );
        // Ethereum
        assert_eq!(
            which_cryptocurrency("0xaae47eae4ddd4877e0ae0bc780cfaee3cc3b52cb"),
            Some("Ethereum")
        );
        // Litecoin
        assert_eq!(
            which_cryptocurrency("LQ4i7FLNhfCC9GXw682mS1NzvVKbtJAFZq"),
            Some("Litecoin")
        );
        // Dodgecoin
        assert_eq!(
            which_cryptocurrency("D6K2nqqQKycTucCSFSHhpiig4yQ6NPQRf9"),
            Some("Dodgecoin")
        );
        // Dash
        assert_eq!(
            which_cryptocurrency("XqLYPDTADW6EYuQmTcEAx81o8EHTKwqTK8"),
            Some("Dash")
        );
        // Monero
        assert_eq!(which_cryptocurrency("41gYNjXMeXaTmZFVv645A1HRVoA637cXFGbDdLV8Gn5hLvfxfRLKigUTvm2HVZhBzDVPeGpDy71qxASTpRFgepDwLexA8Ti"), Some("Monero"));
        // Neo
        assert_eq!(
            which_cryptocurrency("AeHauBkGkHPTxh4PEUhNr7WRgivmcdCRnR"),
            Some("Neo")
        );
        // Ripple
        assert_eq!(
            which_cryptocurrency("rUocf1ixKzTuEe34kmVhRvGqNCofY1NJzV"),
            Some("Ripple")
        );
        // No coin identified
        assert_eq!(which_cryptocurrency("LQ4i7FLNbtJAFZq"), None);
    }

    #[test]
    fn test_is_cryptocurrency_any() {
        assert!(is_cryptocurrency_any("D6K2nqqQKycTucCSFSHhpiig4yQ6NPQRf9"));
        assert!(!is_cryptocurrency_any("LQ4i7FLNbtJAFZq"));
    }

    #[test]
    fn test_is_bitcoin() {
        assert!(is_bitcoin("1GiWxH6PzSSmbdcK72XfGpqhjSb6nae6h9"))
    }

    #[test]
    fn test_is_bitcoin_cash() {
        assert!(is_bitcoin_cash(
            "qppjlghjlwg6tgxv7ffhvs43rlul0kpp4c0shk4dr6"
        ))
    }

    #[test]
    fn test_is_ethereum() {
        assert!(is_ethereum("0xaae47eae4ddd4877e0ae0bc780cfaee3cc3b52cb"))
    }

    #[test]
    fn test_is_litecoin() {
        assert!(is_litecoin("LQ4i7FLNhfCC9GXw682mS1NzvVKbtJAFZq"))
    }

    #[test]
    fn test_is_dogecoin() {
        assert!(is_dogecoin("D6K2nqqQKycTucCSFSHhpiig4yQ6NPQRf9"))
    }

    #[test]
    fn test_is_dash() {
        assert!(is_dash("XqLYPDTADW6EYuQmTcEAx81o8EHTKwqTK8"))
    }

    #[test]
    fn test_is_monero() {
        assert!(is_monero("41gYNjXMeXaTmZFVv645A1HRVoA637cXFGbDdLV8Gn5hLvfxfRLKigUTvm2HVZhBzDVPeGpDy71qxASTpRFgepDwLexA8Ti"))
    }

    #[test]
    fn test_is_neo() {
        assert!(is_neo("AeHauBkGkHPTxh4PEUhNr7WRgivmcdCRnR"))
    }

    #[test]
    fn test_is_ripple() {
        assert!(is_ripple("rUocf1ixKzTuEe34kmVhRvGqNCofY1NJzV"));
        assert!(!is_ripple("RegQueryValueExA"));
    }
}
