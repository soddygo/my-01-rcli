use std::any;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Read};
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use chacha20poly1305::{aead::{AeadCore, AeadInPlace, KeyInit, OsRng}, ChaCha20Poly1305, ChaChaPoly1305, Key, Nonce};
use crate::{process_genpass, TextChipFormat, TextSignFormat};

pub trait TextSigner {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}


pub struct ChaCha20Poly1305Wrapper {
    key: Key,
}


impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes() == sig)
    }
}


impl TextSigner for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = self.key.sign(&buf);
        Ok(ret.to_bytes().to_vec())
    }
}

impl TextVerifier for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = (&sig[..64]).try_into()?;
        let signature = Signature::from_bytes(sig);
        Ok(self.key.verify(&buf, &signature).is_ok())
    }
}


impl Blake3 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        // convert &[u8] to &[u8; 32]
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("blake3.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl ChaCha20Poly1305Wrapper {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();

        // Check if the key has the correct length (32 bytes)
        if key.len() != 32 {
            return Err(anyhow!(Error::new(ErrorKind::InvalidData, "Key must be 32 bytes long")));
        }

        // Create a new ChaCha20Poly1305 instance with the provided key

        let cha_cha_key = Key::clone_from_slice(key);

        Ok(Self::new(cha_cha_key))
    }

    pub fn new(key: Key) -> Self {
        Self { key }
    }
    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);


        let mut map = HashMap::new();
        map.insert("ChaCha20Poly1305.txt", key.as_slice().to_vec());
        Ok(map)
    }
}

impl Ed25519Signer {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(key);
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let mut csprng = OsRng;
        let sk: SigningKey = SigningKey::generate(&mut csprng);
        let pk: VerifyingKey = (&sk).into();
        let mut map = HashMap::new();
        map.insert("ed25519.sk", sk.to_bytes().to_vec());
        map.insert("ed25519.pk", pk.to_bytes().to_vec());

        Ok(map)
    }
}

impl Ed25519Verifier {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        let key = VerifyingKey::from_bytes(key)?;
        Ok(Self { key })
    }
}

pub fn process_text_encrypt<U: Read + Sized>(reader: &mut U,
                                             key: impl AsRef<[u8]>, // (ptr, length)
                                             format: TextChipFormat, ) -> Result<Vec<u8>> {
    match format {
        TextChipFormat::ChaCha20Poly1305 => {
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf)?;
            let cha_cha_wrapper = ChaCha20Poly1305Wrapper::try_new(key)?;
            let cipher = ChaCha20Poly1305::new(&cha_cha_wrapper.key);

            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
            let encrypt = cipher.encrypt_in_place(&nonce, b"", &mut buf);
            Ok(buf)
        }
        _ => {
            Err(anyhow!("not support"))
        }
    }
}


pub fn process_text_decrypt(mut buf: Vec<u8>,
                            key: impl AsRef<[u8]>, // (ptr, length)
                            format: TextChipFormat, ) -> Result<Vec<u8>> {
    match format {
        TextChipFormat::ChaCha20Poly1305 => {
            let cha_cha_wrapper = ChaCha20Poly1305Wrapper::try_new(key)?;
            let cipher = ChaCha20Poly1305::new(&cha_cha_wrapper.key);

            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

            let decrypt = cipher.decrypt_in_place(&nonce, b"", &mut buf);

            if decrypt.is_ok() {
                Ok(buf)
            } else {
                Err(anyhow!("decrypt failed,{}",decrypt.expect_err("failed")))
            }
        }
        _ => {
            Err(anyhow!("not support"))
        }
    }
}

pub fn process_text_chip_key_generate(format: TextChipFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextChipFormat::ChaCha20Poly1305 => ChaCha20Poly1305Wrapper::generate(),
    }
}


pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8], // (ptr, length)
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let signer: Box<dyn TextSigner> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Signer::try_new(key)?),
    };

    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sig: &[u8],
    format: TextSignFormat,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Verifier::try_new(key)?),
    };
    verifier.verify(reader, sig)
}

pub fn process_text_key_generate(format: TextSignFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use base64::engine::general_purpose::STANDARD;
    use serde_json::Value::String;
    use tokio::io::AsyncReadExt;
    use crate::get_reader;

    const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");

    #[test]
    fn test_process_text_sign() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let mut reader1 = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = process_text_sign(&mut reader, KEY, format)?;
        let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_verify() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = "33Ypo4rveYpWmJKAiGnnse-wHQhMVujjmcVkV4Tl43k";
        let sig = URL_SAFE_NO_PAD.decode(sig)?;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }


    #[test]
    fn test_process_text_encrypt() -> Result<()> {
        let format = TextChipFormat::ChaCha20Poly1305;
        let file_key_content = crate::get_content("./fixtures/ChaCha20Poly1305.txt")?;


        let cha_cha_wrapper = ChaCha20Poly1305Wrapper::try_new(file_key_content.clone())?;
        let cipher = ChaCha20Poly1305::new(&cha_cha_wrapper.key);

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

        // let mut reader = "plaintext message".to_string();
        let mut buffer: Vec<u8> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
        buffer.extend_from_slice(b"plaintext message");
        let mut buftest = process_text_readtest(&mut buffer.as_slice());

        // let encrypt = cipher.encrypt_in_place(&nonce, b"", &mut buftest);
        let mut ret = process_text_encrypt(&mut buftest.as_slice(), &file_key_content, format)?;

        let decrypt = cipher.decrypt_in_place(&nonce, b"", &mut ret);


        //转base64 打印
        let content = std::string::String::from_utf8(ret).unwrap();

        println!("content={}", content);


        Ok(())
    }

    pub fn process_text_readtest(reader: &mut impl Read) -> Vec<u8> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf);

        buf
    }


    #[test]
    fn test_process_chacha20() -> Result<()> {
        let file_key_content = crate::get_content("./fixtures/ChaCha20Poly1305.txt")?;


        let cha_cha_wrapper = ChaCha20Poly1305Wrapper::try_new(file_key_content)?;
        let cipher = ChaCha20Poly1305::new(&cha_cha_wrapper.key);

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message


        let mut buffer: Vec<u8> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
        buffer.extend_from_slice(b"plaintext message");

// Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
        cipher.encrypt_in_place(&nonce, b"", &mut buffer);
        println!("ret={}", buffer.len());
        let base64_reader = crate::process_encode(&mut buffer.as_slice(), crate::cli::Base64Format::Standard)?;
        println!("base64_reader={}", base64_reader);

// `buffer` now contains the message ciphertext
        assert_ne!(&buffer, b"plaintext message");

        let mut base64_reader_decocde = crate::process_decode(&mut base64_reader.as_bytes(), crate::cli::Base64Format::Standard)?;


// Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
        cipher.decrypt_in_place(&nonce, b"", &mut base64_reader_decocde);

        let out = std::string::String::from_utf8(base64_reader_decocde.clone())?;
        println!("out={}", out);
        assert_eq!(&base64_reader_decocde, b"plaintext message");

        Ok(())
    }

    #[test]
    fn test_process_text_decrypt() -> Result<()> {
        let mut base64_reader = "ESKg0QDwuKGYWbXOT31O47YK6a78Ga157c0xPvlQZf6Y".to_string();
        //base64解码
        let mut reader_vec = crate::process_decode(&mut base64_reader.as_bytes(), crate::cli::Base64Format::Standard)?;

        let format = TextChipFormat::ChaCha20Poly1305;
        let file_key_content = crate::get_content("./fixtures/ChaCha20Poly1305.txt")?;

        let ret = process_text_decrypt(reader_vec, &file_key_content, format)?;
        //转base64 打印
        let content = std::string::String::from_utf8(ret).unwrap();

        println!("{}", content);

        Ok(())
    }
}
