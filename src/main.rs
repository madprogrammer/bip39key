use anyhow::Result;
use clap::Parser;

use bip39key::{cert, derive};

/// Deterministic GPG key generation from BIP39 seed phrases
#[derive(Parser)]
#[command(name = "bip39key", version, about)]
struct Args {
    /// BIP39 mnemonic phrase
    #[arg(short = 'P', long)]
    phrase: String,

    /// BIP39 passphrase
    #[arg(short = 'p', long, default_value_t = String::new())]
    passphrase: String,

    /// User ID for the key (e.g., 'Name <email>')
    #[arg(short = 'u', long)]
    userid: String,

    /// Key creation timestamp as Unix seconds
    #[arg(short = 't', long)]
    timestamp: u64,

    /// Generate primary key only, without subkeys
    #[arg(long)]
    no_subkeys: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let seed = derive::mnemonic_to_seed(&args.phrase, &args.passphrase)?;

    let cert = if args.no_subkeys {
        let primary = derive::derive_primary_only(&seed);
        cert::build_cert_primary_only(&primary, &args.userid, args.timestamp)?
    } else {
        eprintln!(
            "WARNING: All keys are derived from the same seed phrase. \
             A compromised mnemonic compromises all derived keys."
        );
        let keys = derive::derive_all(&seed);
        cert::build_cert(&keys, &args.userid, args.timestamp)?
    };

    let armored = cert::cert_to_armored(&cert)?;
    println!("{}", armored);

    Ok(())
}
