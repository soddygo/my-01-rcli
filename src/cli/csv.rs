use clap::Parser;

#[derive(Debug,Clone,Copy)]
pub enum OutputFormat{
    Json,
    Yaml,
}

#[derive(Debug,Parser)]
pub struct CsvOpts{
    #[arg(short,long,value_parser)]
    pub input :String,

    pub output:Option<String>,

    pub format:OutputFormat,

    pub delimiter:char,

    pub header:bool,

}