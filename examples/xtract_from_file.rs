use ioc_extract::extract_from_file;

fn main() {
    let ioc = extract_from_file("assets/sample.txt");
    println!("IOC's:\n{:#?}", ioc);
}
