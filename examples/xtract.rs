use ioc_extract::Artifacts;

fn main() {
    let x = "there are ips in this test\nexample.ini\n192.168.21.21 and ::ffff:127.0.0.1\nthe cidrs are:\n2001:0DB8:1234::/48 and \n10.0.0.0/8\n\n";
    let x = x.to_owned() + "check out https://www.google.com or www.google.com";
    let ioc = Artifacts::from_str(&x);
    println!("IOC's:\n{:#?}", ioc);
}
