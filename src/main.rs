#![allow(dead_code)]
#![allow(unused_variables)]

mod cli;
mod core;
mod rate_limit;

use clap::Parser;
use cli::{Cli, Commands};
use core::Target;

/*fn main() {
    let domain = Target::Domain("example.com".to_string());
    let ip = Target::IpAddr("8.8.8.8".to_string());

    println!("Target 1: {} → {}", domain.kind(), domain.value());
    println!("Target 2: {} → {}", ip.kind(), ip.value());
}*/

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let domain = Target::Domain("example.com".to_string());
    let ip = Target::IpAddr("8.8.8.8".to_string());
    println!("Target 1: {} → {}", domain.kind(), domain.value());
    println!("Target 2: {} → {}", ip.kind(), ip.value());

    match args.command {
        Commands::Scan {
            target, modules, ..
        } => {
            println!("Starting scan on {target} with modules: {modules}");
            // Here you'll initialize the limiter manager using args.global_rps, etc.
            //run_scan(&args, target, modules).await?;
        }
    }

    Ok(())
}
