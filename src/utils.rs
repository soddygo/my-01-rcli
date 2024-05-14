use std::io::Read;

use anyhow::Result;

pub fn get_reader(input: &str) -> Result<Box<dyn Read>> {
    if input == "-" {
        return Ok(Box::new(std::io::stdin()));
    }
    let file = std::fs::File::open(input)?;
    Ok(Box::new(file))
}


pub fn get_content(input: &str) -> Result<Vec<u8>> {
    let mut reader = get_reader(input)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}
