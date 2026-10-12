//! webauthn.dll backend: no admin rights needed (unlike raw HID), but every
//! call pops the Windows consent dialog and PIN/UV is forced by the broker.
//!
//! Uses raw `hmac-secret` + `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG`,
//! not the `bEnablePrf` convenience surface (which hashes the salt with a
//! `"WebAuthn PRF"` prefix) -- needed to derive the same secret as ctap for
//! the same credential.

use hmacseal_common as proto;
use windows::core::{Error as WinError, BOOL, HSTRING, PCWSTR};
use windows::Win32::Foundation::HWND;
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use zeroize::Zeroizing;

use super::Backend;

pub struct WinApiBackend;

impl WinApiBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Backend for WinApiBackend {
    fn pin_required(&self) -> bool {
        true
    }

    fn make_credential(&self, rpid: &str, label: &str) -> anyhow::Result<(Vec<u8>, bool)> {
        let hwnd = get_hwnd();

        let client_data_json = format!(r#"{{"type":"webauthn.create","challenge":"","origin":"https://{rpid}"}}"#);

        let rp_id_h = HSTRING::from(rpid);
        let rp_name_h = HSTRING::from("hmacd");
        let rp_info = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: PCWSTR(rp_id_h.as_ptr()),
            pwszName: PCWSTR(rp_name_h.as_ptr()),
            pwszIcon: PCWSTR::null(),
        };

        let mut user_id = random_bytes::<16>()?;
        let user_name_h = HSTRING::from(label);
        let user_info = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: user_id.len() as u32,
            pbId: user_id.as_mut_ptr(),
            pwszName: PCWSTR(user_name_h.as_ptr()),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: PCWSTR(user_name_h.as_ptr()),
        };

        let cose_param = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let cose_params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &cose_param as *const _ as *mut _,
        };

        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_data_json.len() as u32,
            pbClientDataJSON: client_data_json.as_ptr() as *mut u8,
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        let mut want_hmac_secret = BOOL(1);
        let hmac_ext = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: std::mem::size_of::<BOOL>() as u32,
            pvExtension: &mut want_hmac_secret as *mut BOOL as *mut _,
        };
        let extensions = WEBAUTHN_EXTENSIONS {
            cExtensions: 1,
            pExtensions: &hmac_ext as *const _ as *mut _,
        };

        let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: 60_000,
            Extensions: extensions,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            bRequireResidentKey: BOOL(0),
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            ..Default::default()
        };

        let attestation = unsafe {
            WebAuthNAuthenticatorMakeCredential(hwnd, &rp_info, &user_info, &cose_params, &client_data, Some(&options as *const _))
        }
        .map_err(|e| hr_err("WebAuthNAuthenticatorMakeCredential", e))?;

        let result = unsafe {
            let att = &*attestation;
            let id = std::slice::from_raw_parts(att.pbCredentialId, att.cbCredentialId as usize).to_vec();
            // bPrfEnabled only exists from attestation struct version 5 on.
            let hmac_enabled = att.dwVersion >= 5 && att.bPrfEnabled.as_bool();
            (id, hmac_enabled)
        };

        unsafe { WebAuthNFreeCredentialAttestation(Some(attestation)) };
        Ok(result)
    }

    fn derive(&self, rpid: &str, credential_id: &[u8], salt: [u8; proto::SALT_LEN], _use_pin: bool) -> anyhow::Result<Zeroizing<[u8; proto::SECRET_LEN]>> {
        let hwnd = get_hwnd();

        // Plain `&str` doesn't satisfy GetAssertion's generic Param<PCWSTR> bound in windows-rs 0.62.
        let rpid_h = HSTRING::from(rpid);
        let rpid_pcwstr = PCWSTR(rpid_h.as_ptr());

        let client_data_json = format!(r#"{{"type":"webauthn.get","challenge":"","origin":"https://{rpid}"}}"#);
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_data_json.len() as u32,
            pbClientDataJSON: client_data_json.as_ptr() as *mut u8,
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        let mut cred_id = credential_id.to_vec();
        let allow_cred = WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: cred_id.len() as u32,
            pbId: cred_id.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        };
        let allow_list = WEBAUTHN_CREDENTIALS {
            cCredentials: 1,
            pCredentials: &allow_cred as *const _ as *mut _,
        };

        let mut salt_bytes = salt;
        let mut hmac_salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: salt_bytes.len() as u32,
            pbFirst: salt_bytes.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: std::ptr::null_mut(),
        };
        let mut hmac_salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut hmac_salt,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: std::ptr::null_mut(),
        };

        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: 60_000,
            CredentialList: allow_list,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            dwFlags: WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG, // raw salt, no PRF hash; see module doc
            pHmacSecretSaltValues: &mut hmac_salt_values,
            ..Default::default()
        };

        let assertion = unsafe { WebAuthNAuthenticatorGetAssertion(hwnd, rpid_pcwstr, &client_data, Some(&options as *const _)) }
            .map_err(|e| hr_err("WebAuthNAuthenticatorGetAssertion", e))?;

        let result = unsafe {
            let a = &*assertion;
            if a.dwVersion < 3 || a.pHmacSecret.is_null() {
                WebAuthNFreeAssertion(assertion);
                anyhow::bail!("authenticator did not return an hmac-secret value (touch declined, or credential has no hmac-secret)");
            }
            let hs = &*a.pHmacSecret;
            let out = std::slice::from_raw_parts(hs.pbFirst, hs.cbFirst as usize);
            if out.len() != proto::SECRET_LEN {
                WebAuthNFreeAssertion(assertion);
                anyhow::bail!("unexpected hmac-secret length {} (wanted {})", out.len(), proto::SECRET_LEN);
            }
            let mut secret = [0u8; proto::SECRET_LEN];
            secret.copy_from_slice(out);
            secret
        };

        unsafe { WebAuthNFreeAssertion(assertion) };
        Ok(Zeroizing::new(result))
    }
}

fn get_hwnd() -> HWND {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0.is_null() {
            GetConsoleWindow()
        } else {
            hwnd
        }
    }
}

fn hr_err(context: &str, e: WinError) -> anyhow::Error {
    anyhow::anyhow!("{context}: {e} (hr=0x{:08X})", e.code().0 as u32)
}

fn random_bytes<const N: usize>() -> anyhow::Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| anyhow::anyhow!("getrandom failed: {e}"))?;
    Ok(buf)
}
