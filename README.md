# IOC Extract
[![Linux x86_64](https://github.com/marirs/ioc_extract-rs/actions/workflows/linux_x86_64.yml/badge.svg)](https://github.com/marirs/ioc_extract-rs/actions/workflows/linux_x86_64.yml)
[![Linux Arm7](https://github.com/marirs/ioc_extract-rs/actions/workflows/linux_arm.yml/badge.svg)](https://github.com/marirs/ioc_extract-rs/actions/workflows/linux_arm.yml)
[![macOS](https://github.com/marirs/ioc_extract-rs/actions/workflows/macos.yml/badge.svg)](https://github.com/marirs/ioc_extract-rs/actions/workflows/macos.yml)
[![Windows](https://github.com/marirs/ioc_extract-rs/actions/workflows/windows.yml/badge.svg)](https://github.com/marirs/ioc_extract-rs/actions/workflows/windows.yml)
[![GitHub license](https://img.shields.io/github/license/marirs/ioc_extract-rs)](https://github.com/marirs/ioc_extract-rs/blob/master/LICENSE)

Extract indicators like urls,domains,ip,emails,etc... from a given string or a Text file.

### Requirements

- Rust 1.56+ (edition 2021)

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
LICENSE: MIT