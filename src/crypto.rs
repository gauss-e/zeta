use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use url::Url;

pub struct UrlCrypto {
    cipher: Aes256Gcm,
}

impl UrlCrypto {
    pub fn from_key(key: &[u8; 32]) -> anyhow::Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("failed to init cipher: {e}"))?;
        Ok(Self { cipher })
    }

    pub fn decrypt_to_url(&self, encrypted: &str) -> anyhow::Result<Url> {
        let raw = URL_SAFE_NO_PAD
            .decode(encrypted)
            .map_err(|e| anyhow::anyhow!("invalid encrypted url encoding: {e}"))?;

        if raw.len() <= 12 {
            anyhow::bail!("invalid encrypted payload: too short");
        }

        let (nonce_raw, cipher_raw) = raw.split_at(12);

        let plain = self
            .cipher
            .decrypt(Nonce::from_slice(nonce_raw), cipher_raw)
            .map_err(|_| anyhow::anyhow!("url decrypt failed"))?;

        let plain_str = String::from_utf8(plain)
            .map_err(|_| anyhow::anyhow!("decrypted url is not valid utf-8"))?;

        let parsed =
            Url::parse(&plain_str).map_err(|e| anyhow::anyhow!("decrypted url is invalid: {e}"))?;

        match parsed.scheme() {
            "http" | "https" => Ok(parsed),
            _ => anyhow::bail!("decrypted url must be http or https"),
        }
    }

    #[allow(dead_code)]
    pub fn encrypt_url(&self, url: &str) -> anyhow::Result<String> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let encrypted = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), url.as_bytes())
            .map_err(|_| anyhow::anyhow!("failed to encrypt url"))?;

        let mut payload = Vec::with_capacity(12 + encrypted.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&encrypted);

        Ok(URL_SAFE_NO_PAD.encode(payload))
    }
}
