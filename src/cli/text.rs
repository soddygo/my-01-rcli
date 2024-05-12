use std::fmt::Display;
use std::path::PathBuf;
use std::str::FromStr;
use clap::Parser;
use enum_dispatch::enum_dispatch;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokio::fs;
use crate::{CmdExecutor, get_content, get_reader, process_text_key_generate, process_text_sign, process_text_verify};

use super::verify_file;
use super::verify_path;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum TextSubCommand {
    #[command(about = "sign a text with a private/session key and return a signature ")]
    Sign(TextSingOpts),
    #[command(about = "verify a text with a public/session key and a signature")]
    Verify(TextVerifyOpts),
    #[command(about = "generate a key pair for signing and verifying texts")]
    Generate(KeyGenerateOpts),
}

#[derive(Debug, Parser)]
pub struct TextSingOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_path)]
    pub key: String,
    #[arg(long, default_value = "blake3", value_parser = parse_text_sign_format)]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct TextVerifyOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(long)]
    pub sig: String,

    #[arg(long, default_value = "blake3", value_parser = parse_text_sign_format)]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct KeyGenerateOpts {
    #[arg(short, long, default_value = "blake3", value_parser = parse_text_sign_format)]
    pub format: TextSignFormat,

    #[arg(short, long, value_parser = verify_path)]
    pub output_path: PathBuf,

}

#[derive(Debug, Copy, Clone)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
}

fn parse_text_sign_format(format: &str) -> Result<TextSignFormat, anyhow::Error> {
    format.parse()
}

impl FromStr for TextSignFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(TextSignFormat::Blake3),
            "ed25519" => Ok(TextSignFormat::Ed25519),
            _ => Err(anyhow::anyhow!("Invalid format"))
        }
    }
}

impl From<TextSignFormat> for &str {
    fn from(format: TextSignFormat) -> Self {
        match format {
            TextSignFormat::Blake3 => {
                "blake3"
            }
            TextSignFormat::Ed25519 => {
                "ed25519"
            }
        }
    }
}

impl Display for TextSignFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<&str>::into(*self))
    }
}


impl CmdExecutor for TextSingOpts {
    async fn execute(self) -> Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = get_content(&self.key)?;
        let sig = process_text_sign(&mut reader, &key, self.format)?;
        // base64 output
        let encoded = URL_SAFE_NO_PAD.encode(sig);
        println!("{}", encoded);
        Ok(())
    }
}

impl CmdExecutor for TextVerifyOpts {
    async fn execute(self) -> Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = get_content(&self.key)?;
        let decoded = URL_SAFE_NO_PAD.decode(&self.sig)?;
        let verified = process_text_verify(&mut reader, &key, &decoded, self.format)?;
        if verified {
            println!("✓ Signature verified");
        } else {
            println!("⚠ Signature not verified");
        }
        Ok(())
    }
}

impl CmdExecutor for KeyGenerateOpts {
    async fn execute(self) -> Result<()> {
        let key = process_text_key_generate(self.format)?;
        for (k, v) in key {
            fs::write(self.output_path.join(k), v).await?;
        }
        Ok(())
    }
}