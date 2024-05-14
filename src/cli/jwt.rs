use std::fmt::Display;
use std::str::FromStr;
use anyhow::{anyhow, Result};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use crate::{CmdExecutor, JwtDecoder, JwtDecoderWrapper, JwtEncoder, JwtEncoderWrapper, JwtPlayerData};
use super::verify_file;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum JwtSubCommand {
    #[command(name = "encode", about = "encode jwt")]
    Encode(JwtEncodeOpts),
    #[command(name = "decode", about = "decode jwt")]
    Decode(JwtDecodeOpts),

}


#[derive(Debug, Parser)]
pub struct JwtEncodeOpts {
    #[arg(long)]
    pub data: String,
    #[arg(long, value_parser = verify_file)]
    pub secret: String,
    #[arg(long, default_value = "HS256", value_parser = parse_algorithm_format)]
    pub algorithm: AlgorithmFormat,

}

#[derive(Debug, Parser)]
pub struct JwtDecodeOpts {
    #[arg(long)]
    pub data: String,
    #[arg(long, value_parser = verify_file)]
    pub secret: String,
    #[arg(long, default_value = "HS256", value_parser = parse_algorithm_format)]
    pub algorithm: AlgorithmFormat,
}

#[derive(Debug, Clone, Copy)]
pub enum AlgorithmFormat {
    HS256,
}


fn parse_algorithm_format(algorithm_format: &str) -> Result<AlgorithmFormat, anyhow::Error> {
    algorithm_format.parse()
}

impl FromStr for AlgorithmFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HS256" => Ok(AlgorithmFormat::HS256),
            _ => Err(anyhow::anyhow!("Invalid format"))
        }
    }
}

impl From<AlgorithmFormat> for &str {
    fn from(value: AlgorithmFormat) -> Self {
        match value {
            AlgorithmFormat::HS256 => "HS256",
        }
    }
}

impl Display for AlgorithmFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlgorithmFormat::HS256 => write!(f, "{}", Into::<&str>::into(*self)),
        }
    }
}

impl CmdExecutor for JwtEncodeOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let jwt_encoder_wrapper = JwtEncoderWrapper::try_new(self.secret, self.algorithm)?;

        let ret = jwt_encoder_wrapper.encode(self.data.clone())?;
        println!("{}", ret);

        Ok(())
    }
}

impl CmdExecutor for JwtDecodeOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let jwt_decoder_wrapper = JwtDecoderWrapper::try_new(self.secret, self.algorithm)?;

        let ret = jwt_decoder_wrapper.decode(&mut self.data.as_bytes())?;
        println!("{}", ret);

        Ok(())
    }
}