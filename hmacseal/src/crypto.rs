//! Identical to sshseal's crypto.rs, except the AEAD key+IV are derived from
//! a FIDO2 hmac-secret output instead of a deterministic ed25519 signature.

use std::io;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: [u8; 4] = *b"HSE1";
pub const SALT_LEN: usize = 32;
const FINGERPRINT_LEN: usize = 32; // raw SHA256 digest of the credential id
const HEADER_LEN: usize = MAGIC.len() + FINGERPRINT_LEN + SALT_LEN;

pub struct Header {
    pub fingerprint: [u8; FINGERPRINT_LEN],
    pub salt: [u8; SALT_LEN],
}

impl Header {
    pub fn parse(data: &[u8]) -> io::Result<(Header, &[u8])> {
        if data.len() < HEADER_LEN || data[..4] != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not an hmacseal blob"));
        }
        let fingerprint = data[4..4 + FINGERPRINT_LEN].try_into().unwrap();
        let salt = data[4 + FINGERPRINT_LEN..HEADER_LEN].try_into().unwrap();
        Ok((Header { fingerprint, salt }, &data[HEADER_LEN..]))
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.fingerprint);
        out.extend_from_slice(&self.salt);
    }
}

/// Derives the AES-256-GCM key+nonce from an hmac-secret output.
fn derive(secret: &[u8; 32]) -> (Aes256Gcm, [u8; 12]) {
    let hkdf = Hkdf::<Sha256>::new(None, secret);
    let mut okm: Zeroizing<[u8; 44]> = Zeroizing::new([0u8; 44]);
    hkdf.expand(b"hmacseal-v1", &mut *okm)
        .expect("44 bytes is within HKDF-SHA256's output limit");
    let cipher = Aes256Gcm::new_from_slice(&okm[..32]).expect("okm[..32] is exactly 32 bytes");
    (cipher, okm[32..].try_into().unwrap())
}

pub fn seal(plaintext: &[u8], secret: &[u8; 32]) -> Vec<u8> {
    let (cipher, iv) = derive(secret);
    cipher
        .encrypt(Nonce::from_slice(&iv), plaintext)
        .expect("AES-256-GCM encryption of an in-memory buffer does not fail")
}

pub fn unseal(ciphertext: &[u8], secret: &[u8; 32]) -> io::Result<Vec<u8>> {
    let (cipher, iv) = derive(secret);
    cipher
        .decrypt(Nonce::from_slice(&iv), ciphertext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed (wrong key or corrupted data)"))
}
