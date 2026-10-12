//! ctap-hid-fido2 backend: raw HID access to the key, no OS broker
//! involved. PIN is optional and respected as asked (see `Backend::derive`).

use ctap_hid_fido2::fidokey::{AssertionExtension, CredentialExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory};
use hmacseal_common as proto;
use zeroize::Zeroizing;

use super::Backend;

pub struct CtapBackend {
    device: FidoKeyHid,
}

impl CtapBackend {
    pub fn new() -> anyhow::Result<Self> {
        let cfg = Cfg::init();
        Ok(Self { device: FidoKeyHidFactory::create(&cfg)? })
    }
}

impl Backend for CtapBackend {
    fn pin_required(&self) -> bool {
        false
    }

    fn make_credential(&self, rpid: &str, _label: &str) -> anyhow::Result<(Vec<u8>, bool)> {
        let challenge = random_challenge()?;

        // use_pin only affects derive(); both credRandom variants are created regardless.
        let args = MakeCredentialArgsBuilder::new(rpid, &challenge)
            .without_pin_and_uv()
            .extensions(&[CredentialExtension::HmacSecret(Some(true))])
            .build();

        let attestation = self.device.make_credential_with_args(&args)?;

        let hmac_enabled = attestation
            .extensions
            .iter()
            .any(|e| matches!(e, CredentialExtension::HmacSecret(Some(true))));

        Ok((attestation.credential_descriptor.id, hmac_enabled))
    }

    fn derive(&self, rpid: &str, credential_id: &[u8], salt: [u8; proto::SALT_LEN], use_pin: bool) -> anyhow::Result<Zeroizing<[u8; proto::SECRET_LEN]>> {
        let challenge = random_challenge()?;

        let pin: Option<Zeroizing<String>> = if use_pin {
            Some(Zeroizing::new(rpassword::prompt_password("YubiKey PIN: ")?))
        } else {
            None
        };

        let ext = AssertionExtension::HmacSecret(Some(salt));
        let mut builder = GetAssertionArgsBuilder::new(rpid, &challenge);
        builder = match &pin {
            Some(p) => builder.pin(p.as_str()),
            None => builder.without_pin_and_uv(),
        };
        let args = builder.credential_id(credential_id).extensions(&[ext]).build();

        let assertions = self.device.get_assertion_with_args(&args)?;
        let found = assertions[0].extensions.iter().find_map(|e| match e {
            AssertionExtension::HmacSecret(Some(secret)) => Some(*secret),
            _ => None,
        });
        found
            .map(Zeroizing::new)
            .ok_or_else(|| anyhow::anyhow!("authenticator did not return an hmac-secret value (touch declined, or credential has no hmac-secret)"))
    }
}

fn random_challenge() -> anyhow::Result<[u8; 32]> {
    let mut c = [0u8; 32];
    getrandom::getrandom(&mut c).map_err(|e| anyhow::anyhow!("getrandom failed: {e}"))?;
    Ok(c)
}
