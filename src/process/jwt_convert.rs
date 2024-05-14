use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use jsonwebtoken::{decode, DecodingKey, encode, EncodingKey, Header, Validation};
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub trait JwtEncoder {
    fn encode(&self, data: String) -> Result<String>;
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

///jwt 测试数据结果对象
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtPlayerData {
    data: String,
    exp: i64,
}

impl JwtPlayerData {
    fn new(data: String) -> Self {
        Self {
            data,
            exp: (SystemTime::now()
                .checked_add(Duration::from_secs(3600)) // 过期时间为1小时
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()) as i64,
        }
    }
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
    fn encode(&self, data: String) -> Result<String> {
        let jwt_player_data = JwtPlayerData::new(data);
        let token = encode(&self.header, &jwt_player_data, &self.key);

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
        let token_message = decode::<JwtPlayerData>(&token, &self.key, &self.validation);
        match token_message {
            Ok(message) => {
                let message = serde_json::to_string(&message.claims)?;
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
    use crate::JwtPlayerData;

    #[test]
    fn test_jwt() -> Result<()> {
        let secret = "secret";

        let algorithm = Algorithm::HS256;

        let header = Header::new(algorithm);

        let jwt_player_data = JwtPlayerData::new("hello world".to_string());

        let token = encode(&header, &jwt_player_data, &EncodingKey::from_secret(secret.as_ref()))?;

        println!("加密={}", token);
        let token_message = decode::<JwtPlayerData>(&token,
                                                    &DecodingKey::from_secret(secret.as_ref()),
                                                    &Validation::new(algorithm));

        match token_message {
            Ok(message) => {
                let json = serde_json::to_string(&message.claims)?;
                println!("解码={:?}", json);
            }
            Err(err) => {
                return Err(anyhow::anyhow!("decode error,err={}",err));
            }
        }


        Ok(())
    }
}