use std::error::Error;
use aes::{Aes128};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Ecb};
use md5;

pub struct UrlCrypto {
    key: String
}

type Aes128Ecb = Ecb<Aes128, Pkcs7>;

impl UrlCrypto {
    pub fn from_password(password: &str) -> Result<Self, Box<dyn Error>> {
        Ok(Self{key: String::from(password)})
    }

    pub fn decrypt_param(&self, encrypted: &str) -> Result<String, Box<dyn Error>> {
        let (mode, payload) = parse_mode(encrypted)?;

        match mode {
            DecryptMode::BASE64 => {
                let decoded = decode_param_by_base64(payload)?;
                Ok(String::from_utf8(decoded)?)
            }
            DecryptMode::AES => decode_param_by_aes(&*self.key, payload),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum DecryptMode {
    BASE64,
    AES,
}

fn parse_mode(input: &str) -> anyhow::Result<(DecryptMode, &str)> {
    if let Some(rest) = input.strip_prefix("{BASE64}") {
        return Ok((DecryptMode::BASE64, rest));
    }
    if let Some(rest) = input.strip_prefix("{AES}") {
        return Ok((DecryptMode::AES, rest));
    }
    anyhow::bail!("missing or unsupported encryption prefix; expected {{BASE64}} or {{AES}}")
}

fn decode_param_by_base64(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| STANDARD_NO_PAD.decode(input))
        .or_else(|_| STANDARD.decode(input))?;
    Ok(decoded)
}

fn decode_param_by_aes(key: &str,
            encrypted_bytes: &str) -> Result<String, Box<dyn Error>> {
    let key = create_aes_key(key);

    let cipher = Aes128Ecb::new_from_slices(&key, &[])?;

    let cipher_bytes = decode_param_by_base64(encrypted_bytes)?;
    let decrypted_data = cipher.decrypt_vec(cipher_bytes.as_ref())?;

    let plaintext = String::from_utf8(decrypted_data)?;

    Ok(plaintext)
}

fn create_aes_key(secret_key: &str) -> [u8; 16] {
    let key_bytes = secret_key.as_bytes();

    let digest = md5::compute(key_bytes);

    digest.0
}
