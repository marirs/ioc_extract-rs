use ioc_extract::extract_from_file;
use std::{env, process::exit};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("please give filename to extract the ioc's!");
        exit(1);
    }
    let file = args[1].to_owned();

    let ioc = extract_from_file(&file);
    println!("IOC's:\n{:#?}", ioc);
}
