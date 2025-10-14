
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use chrono::Utc;
use omarchy_cert_core::{inspect_remote, days_until_expiry};

#[derive(Parser)]
#[command(name="omarchy-cert-cli")]
#[command(about="Certificate inspector (CLI) for Omarchy", long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect a remote host:port (optionally with SNI)
    Inspect {
        target: String,
        #[arg(long)]
        sni: Option<String>,
    },
    /// Output JSON from inspect (machine-readable)
    InspectJson {
        target: String,
        #[arg(long)]
        sni: Option<String>,
    },
}

fn split_target(s: &str) -> Result<(&str, u16)> {
    if let Some((h, p)) = s.rsplit_once(':') {
        let port: u16 = p.parse().context("invalid port")?;
        Ok((h, port))
    } else {
        anyhow::bail!("target must be host:port");
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Inspect { target, sni } => {
            let (host, port) = split_target(&target)?;
            let report = inspect_remote(host, port, sni.as_deref())?;
            println!("Host: {}:{} (SNI: {:?})", report.host, report.port, report.sni);
            if let Some(leaf) = report.certs.first() {
                let days = days_until_expiry(leaf).unwrap_or_default();
                println!("Leaf Subject : {}", leaf.subject);
                println!("Leaf Issuer  : {}", leaf.issuer);
                println!("Not After    : {:?}", leaf.not_after);
                println!("Days to exp. : {}", days);
                println!("SANs         : {:?}", leaf.san);
            } else {
                println!("No certs parsed.");
            }
            println!("\nChain:");
            for (i, c) in report.certs.iter().enumerate() {
                println!("  [{}] {}", i, c.subject);
                println!("      Issuer: {}", c.issuer);
            }
        }
        Commands::InspectJson { target, sni } => {
            let (host, port) = split_target(&target)?;
            let report = inspect_remote(host, port, sni.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}
