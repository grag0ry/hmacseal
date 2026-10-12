//! Thin client for `hmacd`/`hmacd-winapi`. No FIDO2/HID deps: runs wherever
//! encrypt/decrypt happens, reached via `ssh -R` forwarding `$HMAC_AGENT_SOCKET`.
//! No `Client` struct: each call connects fresh (see protocol crate docs).

use std::io;

use hmacseal_common as proto;
pub use hmacseal_common::Credential;
use zeroize::Zeroizing;

#[cfg(windows)]
const DEFAULT_SOCKET_PATH: &str = r"\\.\pipe\hmacd";
#[cfg(not(windows))]
const DEFAULT_SOCKET_PATH: &str = "/tmp/hmacd.sock";

pub fn socket_path() -> String {
    std::env::var("HMAC_AGENT_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string())
}

pub fn list_credentials(path: &str) -> io::Result<Vec<Credential>> {
    let mut stream = proto::connect(path)?;
    proto::write_frame(&mut *stream, &proto::encode_list_request())?;
    let reply = proto::read_frame(&mut *stream)?;
    proto::decode_list_reply(&reply)
}

pub fn derive(path: &str, credential_id: &[u8], salt: &[u8; proto::SALT_LEN]) -> io::Result<Zeroizing<[u8; proto::SECRET_LEN]>> {
    let mut stream = proto::connect(path)?;
    proto::write_frame(&mut *stream, &proto::encode_derive_request(credential_id, salt))?;
    let reply = proto::read_frame(&mut *stream)?;
    proto::decode_derive_reply(&reply)
}
