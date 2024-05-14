use std::path::PathBuf;

use clap::Parser;
use enum_dispatch::enum_dispatch;

use crate::{CmdExecutor, process_http_server};

use super::verify_path;

#[derive(Debug, Parser)]
#[enum_dispatch(enum_dispatch)]
pub enum HttpSubCommand {
    #[command(about = "Serve a directory over HTTP")]
    Server(HttpServerOpts),
}


#[derive(Debug, Parser)]
pub struct HttpServerOpts {
    #[arg(short, long, value_parser = verify_path, default_value = ".")]
    pub dir: PathBuf,
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,
}


impl CmdExecutor for HttpSubCommand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            HttpSubCommand::Server(opts) => {
                process_http_server(opts.dir.clone(), opts.port).await?;
            }
        }
        Ok(())
    }
}
