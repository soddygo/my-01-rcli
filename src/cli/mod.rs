mod csv;
mod base64;
mod text;
mod genpass;
mod http;

use std::path::{Path, PathBuf};
use clap::{Parser};
use enum_dispatch::enum_dispatch;


pub use self::{csv::*, base64::*,text::*,genpass::*,http::*};

#[derive(Debug, Parser)]
#[command(name = "my-rcli", author, version, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: Subcommand,
}

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum Subcommand {
    #[command(name = "csv", about = "Show CSV,or convert CSV files to other formats")]
    Csv(CsvOpts),

    #[command(subcommand, name = "base64", about = "Base64 encode or decode files")]
    Base64(Base64SubCommand),

    #[command(subcommand, name = "text", about = "Text manipulation commands")]
    Text(TextSubCommand),
    
    #[command(name = "genpass",about="")]
    GenPass(GenPassOpts),

    #[command(subcommand, name = "http", about = "HTTP server")]
    Http(HttpSubCommand),
}

fn verify_file(filename: &str) -> Result<String, &'static str> {
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("file not found")
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(path.into())
    } else {
        Err("path does not exist or is not a directory")
    }
}