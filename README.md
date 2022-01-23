# IOC Extract

Extract indicators like urls,domains,ip,emails,etc... from a given string.

### Requirements

- Rust 1.50+

### Example
```rust
use ioc_extract::extract;

fn main() {
    let x = "there are ips in this test\n192.168.21.21 and ::ffff:127.0.0.1\nthe cidrs are:\n2001:0DB8:1234::/48 and \n10.0.0.0/8\n\n";
    let x = x.to_owned() + "check out https://www.google.com or www.google.com";
    let ioc = extract(&x);
    println!("IOC's:\n{:#?}", ioc);
}
```

### Running the Example
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

---
