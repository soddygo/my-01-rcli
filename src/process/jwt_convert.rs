use std::io::Read;
use jsonwebtoken::{decode, DecodingKey, encode, EncodingKey, Header, Validation};
use anyhow::Result;
use serde::Serialize;

pub trait JwtEncoder {
    fn encode<U: Serialize>(&self, data: &U) -> Result<String>;
}

pub trait JwtDecoder {
    fn decode<U: Read>(&self, data: &mut U) -> Result<String>;
}


pub struct JwtEncoderWrapper {
    key: EncodingKey,
    header: Header,

}


pub struct JwtDecoderWrapper {
    key: DecodingKey,
    validation: Validation,

}


impl JwtEncoderWrapper {
    pub fn try_new(key: String, algorithm: crate::cli::AlgorithmFormat) -> Result<Self> {
        let header = match algorithm {
            crate::cli::AlgorithmFormat::HS256 => {
                let header = Header::new(jsonwebtoken::Algorithm::HS256);
                header
            }
        };

        let key = EncodingKey::from_secret(key.as_bytes());

        Ok(JwtEncoderWrapper::new(key, header))
    }

    pub fn new(key: EncodingKey, header: Header) -> Self {
        JwtEncoderWrapper {
            key,
            header,
        }
    }
}


impl JwtDecoderWrapper {
    pub fn try_new(key: String, algorithm: crate::cli::AlgorithmFormat) -> Result<Self> {
        let validation = match algorithm {
            crate::cli::AlgorithmFormat::HS256 => {
                let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
                validation
            }
        };

        let key = DecodingKey::from_secret(key.as_bytes());

        Ok(JwtDecoderWrapper::new(key, validation))
    }

    pub fn new(key: DecodingKey, validation: Validation) -> Self {
        JwtDecoderWrapper {
            key,
            validation,
        }
    }
}


impl JwtEncoder for JwtEncoderWrapper {
    fn encode<U: Serialize>(&self, data: &U) -> Result<String> {
        let token = encode(&self.header, data, &self.key);

        match token {
            Ok(message) => {
                let message = message;
                Ok(message)
            }
            Err(err) => {
                Err(anyhow::anyhow!("encode error,err={}",err))
            }
        }
    }
}

impl JwtDecoder for JwtDecoderWrapper {
    fn decode<U: Read>(&self, data: &mut U) -> Result<String> {
        let mut buffer = Vec::new();
        data.read_to_end(&mut buffer);
        let token = String::from_utf8(buffer)?;
        let token_message = decode::<String>(&token, &self.key, &self.validation);
        match token_message {
            Ok(message) => {
                let message = message.claims;
                Ok(message)
            }
            Err(err) => {
                Err(anyhow::anyhow!("decode error,err={}",err))
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};
    use anyhow::Result;

    #[test]
    fn test_jwt() -> Result<()> {
        let secret = "secret";

        let algorithm = Algorithm::HS256;

        let header = Header::new(algorithm);

        let token = encode(&header, &"hello world".to_string(), &EncodingKey::from_secret(secret.as_ref())).unwrap();

        println!("加密={}", token);
        let token_message = decode::<String>(&token, &DecodingKey::from_secret(secret.as_ref()), &Validation::new(algorithm));


        println!("解码={}", token_message.unwrap().claims);

        Ok(())
    }
}