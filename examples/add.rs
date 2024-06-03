use ioc_extract::Artifacts;

fn main() {
    let x = "there are ips in this test\nexample.ini\n192.168.21.21 and ::ffff:127.0.0.1\nthe cidrs are:\n2001:0DB8:1234::/48 and \n10.0.0.0/8\n\n";
    let x = x.to_owned() + "check out https://www.google.com or www.google.com";
    let mut ioc_x = Artifacts::from_str(&x).unwrap();

    let y = "there are ips in this test\nexample_two.ini\n192.168.21.25 and ::ffff:127.0.0.3\nthe cidrs are:\n2001:0DB8:1234::/48 and \n10.0.0.0/8\n\n";
    let y = y.to_owned() + "check out https://www.bing.com or www.bing.com";
    let ioc_y = Artifacts::from_str(&y).unwrap();

    let z = "there are ips in this test\nexample_three.ini\n192.168.21.29 and ::ffff:127.0.0.6\nthe cidrs are:\n2001:0DB8:1234::/48 and \n10.0.0.0/8\n\n";
    let z = z.to_owned() + "check out https://www.duckduckgo.com or www.duckduckgo.com";
    let ioc_z = Artifacts::from_str(&z).unwrap();

    println!("IOC's from x:\n{:#?}", ioc_x);
    println!("IOC's from y:\n{:#?}", ioc_y);
    println!("IOC's from z:\n{:#?}", ioc_z);

    println!(
        "IOC's from (x + y + z):\n{:#?}",
        ioc_x.clone() + ioc_y.clone() + ioc_z
    );

    ioc_x += ioc_y;

    println!("new IOC's from x:\n{:#?}", ioc_x);
}
