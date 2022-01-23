# IOC Extract

Extract indicators like urls,domains,ip,emails,etc... from a given string.

### Requirements

- Rust 1.50+

### Example
```bash
$ cargo r --example xtract
     Running `target/debug/examples/xtract`
IOC's:
Some(
    Indicators {
        urls: Some(
            [
                "https://www.google.com",
            ],
        ),
        domains: Some(
            [
                "www.google.com",
            ],
        ),
        emails: None,
        ip_address: Some(
            [
                "10.0.0.0/8",
                "192.168.21.21",
                "2001:0DB8:1234::/48",
                "::ffff:127.0.0.1",
            ],
        ),
        crypto: None,
        registry: None,
    },
)
```