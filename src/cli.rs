// src/cli.rs
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "spiderfoot-rs",
    version,
    about = "Rust reimplementation of SpiderFoot — OSINT automation",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Global maximum requests per second (fallback when no per-domain limit exists)
    #[arg(long, default_value_t = 5.0)]
    pub global_rps: f32,

    /// Global burst size (tokens that can be accumulated)
    #[arg(long, default_value_t = 10)]
    pub global_burst: u32,

    /// Path to TOML config file (can override defaults and add per-domain limits)
    #[arg(short, long)]
    pub config: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a scan
    Scan {
        /// Target (domain, IP, email, etc.)
        target: String,

        /// Module(s) to enable (comma-separated or 'all')
        #[arg(short, long, default_value = "all")]
        modules: String,
        // ... more scan-specific flags later
    },
    // Later: list-modules, list-sources, etc.
}
