mod core;

use core::Target;

fn main() {
    let domain = Target::Domain("example.com".to_string());
    let ip     = Target::IpAddr("8.8.8.8".to_string());

    println!("Target 1: {} → {}", domain.kind(), domain.value());
    println!("Target 2: {} → {}", ip.kind(),     ip.value());
}