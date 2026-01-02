//! Token generation utility.
//!
//! Generates authentication tokens for tunnel clients.

use clap::Parser;
use tun_core::auth::TokenValidator;

/// Generate authentication tokens for tunnel clients.
#[derive(Parser, Debug)]
#[command(name = "tun-token")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The authentication secret (hex-encoded)
    /// If not provided, a new secret will be generated
    #[arg(short, long, env = "TUN_AUTH_SECRET")]
    secret: Option<String>,

    /// Number of tokens to generate
    #[arg(short, long, default_value = "1")]
    count: usize,

    /// Generate a new secret
    #[arg(long)]
    new_secret: bool,
}

fn main() {
    let args = Args::parse();

    let validator = if args.new_secret || args.secret.is_none() {
        let v = TokenValidator::default();
        println!("Generated new secret: {}", v.secret_hex());
        println!("Save this secret to use with tun-server --auth-secret");
        println!();
        v
    } else {
        match TokenValidator::from_hex(args.secret.as_ref().unwrap()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error: Invalid secret - {}", e);
                std::process::exit(1);
            }
        }
    };

    println!("Generated token(s):");
    for i in 0..args.count {
        match validator.generate_token() {
            Ok(token) => {
                if args.count > 1 {
                    println!("  {}: {}", i + 1, token.token);
                } else {
                    println!("  {}", token.token);
                }
            }
            Err(e) => {
                eprintln!("Error generating token: {}", e);
                std::process::exit(1);
            }
        }
    }

    println!();
    println!("Use this token with tun-client --token <TOKEN>");
}

