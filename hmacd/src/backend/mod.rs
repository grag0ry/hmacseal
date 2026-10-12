//! Backend abstraction: how hmacd talks to the physical FIDO2 key.
//! `ctap` (ctap-hid-fido2, raw HID) is always available; `winapi`
//! (webauthn.dll broker) only compiles on Windows.

mod ctap;
#[cfg(windows)]
mod winapi;

use hmacseal_common as proto;
use zeroize::Zeroizing;

pub trait Backend {
    /// True if derive() always requires PIN/UV regardless of what's asked (winapi: broker forces UV).
    fn pin_required(&self) -> bool;

    /// Returns (credential_id, hmac_secret_confirmed).
    fn make_credential(&self, rpid: &str, label: &str) -> anyhow::Result<(Vec<u8>, bool)>;

    fn derive(
        &self,
        rpid: &str,
        credential_id: &[u8],
        salt: [u8; proto::SALT_LEN],
        use_pin: bool,
    ) -> anyhow::Result<Zeroizing<[u8; proto::SECRET_LEN]>>;
}

pub fn default_name() -> &'static str {
    if cfg!(windows) {
        "winapi"
    } else {
        "ctap"
    }
}

pub fn available_names() -> &'static str {
    if cfg!(windows) {
        "ctap, winapi"
    } else {
        "ctap"
    }
}

pub fn by_name(name: &str) -> anyhow::Result<Box<dyn Backend>> {
    match name {
        "ctap" => Ok(Box::new(ctap::CtapBackend::new()?)),
        #[cfg(windows)]
        "winapi" => Ok(Box::new(winapi::WinApiBackend::new())),
        other => anyhow::bail!("unknown backend '{other}' (available: {})", available_names()),
    }
}
