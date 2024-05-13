use std::io::Read;
use crate::cli::Base64Format;
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

pub fn process_encode(reader: &mut dyn Read, format: Base64Format) -> Result<String> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    let encoded = match format {
        Base64Format::Standard => STANDARD.encode(&buf),
        Base64Format::UrlSafe => URL_SAFE_NO_PAD.encode(&buf),
    };
    Ok(encoded)
}


pub fn process_decode(reader: &mut dyn Read, format: Base64Format) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    let decoded = match format {
        Base64Format::Standard => STANDARD.decode(&buf)?,
        Base64Format::UrlSafe => URL_SAFE_NO_PAD.decode(&buf)?,
    };
    // TODO: decoded data might not be string (but for this example, we assume it is)

    Ok(decoded)
}


#[cfg(test)]
mod tests {
    use crate::get_reader;
    use super::*;

    #[test]
    fn test_process_encode() -> Result<()> {
        let input = "./fixtures/b64.txt";
        let mut reader = get_reader(input)?;
        let format = Base64Format::Standard;
        let output = process_encode(&mut reader, format)?;

        print!("{}", output);

        Ok(())
    }

    #[test]
    fn test_process_decode() -> Result<()> {
        let input = "./fixtures/b64_decode.txt";
        let mut reader = get_reader(input)?;
        let format = Base64Format::Standard;
        let ret = process_decode(&mut reader, format)?;

        let output = String::from_utf8(ret)?;
        print!("{}", output);

        Ok(())
    }
}