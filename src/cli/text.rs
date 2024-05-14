use std::fmt::Display;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use enum_dispatch::enum_dispatch;
use tokio::fs;

use crate::{CmdExecutor, get_content, get_reader, process_text_chip_key_generate, process_text_decrypt, process_text_encrypt,
            process_text_key_generate, process_text_sign, process_text_verify,
};

use super::verify_file;
use super::verify_path;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum TextSubCommand {
    #[command(about = "sign a text with a private/session key and return a signature ")]
    Sign(TextSignOpts),
    #[command(about = "verify a text with a public/session key and a signature")]
    Verify(TextVerifyOpts),
    #[command(about = "generate a key pair for signing and verifying texts")]
    Generate(KeyGenerateOpts),
    #[command(about = "generate a key pair for encrypting and decrypting texts")]
    ChipGenerate(ChipKeyGenerateOpts),

    #[command(about = "encrypt a text with a public/session key")]
    Encrypt(EncryptOpts),

    #[command(about = "decrypt a text with a private/session key")]
    Decrypt(DecryptOpts),

}

#[derive(Debug, Parser)]
pub struct EncryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(long, value_parser = verify_file,)]
    pub key: String,
    #[arg(long, value_parser = verify_path, help = "none file path,unique per message")]
    pub nonce_output_path: PathBuf,
    #[arg(long, default_value = "chacha20-poly1305", value_parser = parse_text_chip_format)]
    pub format: TextChipFormat,
}

#[derive(Debug, Parser)]
pub struct DecryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(long, value_parser = verify_file,)]
    pub key: String,
    #[arg(long, value_parser = verify_file, help = "none file path,unique per message")]
    pub nonce_input_path: String,
    #[arg(long, default_value = "chacha20-poly1305", value_parser = parse_text_chip_format)]
    pub format: TextChipFormat,
}

#[derive(Debug, Parser)]
pub struct TextSignOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
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
    #[arg(long, default_value = "blake3", value_parser = parse_text_sign_format)]
    pub format: TextSignFormat,

    #[arg(long, value_parser = verify_path)]
    pub output_path: PathBuf,

}

#[derive(Debug, Parser)]
pub struct ChipKeyGenerateOpts {
    #[arg(long, default_value = "chacha20-poly1305", value_parser = parse_text_chip_format)]
    pub format: TextChipFormat,

    #[arg(long, value_parser = verify_path)]
    pub output_path: PathBuf,

}

#[derive(Debug, Copy, Clone)]
pub enum TextChipFormat {
    ChaCha20Poly1305Format,
}

#[derive(Debug, Copy, Clone)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
}

fn parse_text_sign_format(format: &str) -> Result<TextSignFormat, anyhow::Error> {
    format.parse()
}

fn parse_text_chip_format(format: &str) -> Result<TextChipFormat, anyhow::Error> {
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

impl FromStr for TextChipFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chacha20-poly1305" => Ok(TextChipFormat::ChaCha20Poly1305Format),
            _ => Err(anyhow::anyhow!("Invalid format"))
        }
    }
}

impl From<TextChipFormat> for &str {
    fn from(format: TextChipFormat) -> Self {
        match format {
            TextChipFormat::ChaCha20Poly1305Format => {
                "chacha20-poly1305"
            }
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

impl Display for TextChipFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<&str>::into(*self))
    }
}

impl CmdExecutor for TextSignOpts {
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

impl CmdExecutor for EncryptOpts {
    async fn execute(self) -> Result<()> {
        let mut reader = get_reader(&self.input)?;

        let key = get_content(&self.key)?;

        let (content, _nonce) = process_text_encrypt(&mut reader, &key, self.format)?;

        //转base64 打印
        let base64 = crate::process_encode(&mut content.as_slice(), crate::cli::Base64Format::Standard)?;
        println!("{}", base64);

        //输出 _nonce 内容到文件里,用于下次解密使用
        fs::write(self.nonce_output_path.join("nonce.txt"), _nonce).await?;

        Ok(())
    }
}

impl CmdExecutor for DecryptOpts {
    async fn execute(self) -> Result<()> {
        let mut base64_reader = get_reader(&self.input)?;
        //base64解码
        let mut reader_venc = crate::process_decode(&mut base64_reader, crate::cli::Base64Format::Standard)?;


        let key = get_content(&self.key)?;
        let nonce = get_content(&self.nonce_input_path)?;

        let content = process_text_decrypt(reader_venc, &key, &nonce, self.format)?;

        //转utf8字符串

        let ret = String::from_utf8(content).unwrap();
        println!("{}", ret);

        Ok(())
    }
}

impl CmdExecutor for ChipKeyGenerateOpts {
    async fn execute(self) -> Result<()> {
        let key = process_text_chip_key_generate(self.format)?;
        for (k, v) in key {
            fs::write(self.output_path.join(k), v).await?;
        }
        Ok(())
    }
}