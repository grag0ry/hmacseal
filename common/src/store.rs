//! On-disk credential store (`--store` file), shared format between
//! `hmacd` and `hmacd-winapi`: either backend can drive a credential the
//! other one registered, since the credential lives on the device.

use std::io;

use crate::{from_hex, to_hex, wire::Credential};

/// `pin` picks `credRandomWithUV` vs `credRandomWithoutUV` and never
/// crosses the wire (not part of [`Credential`]). `hmacd-winapi` always
/// writes `pin: true`: webauthn.dll forces UV for hmac-secret regardless of
/// what's requested.
pub struct StoredCredential {
    pub id: Vec<u8>,
    pub pin: bool,
    pub label: String,
}

impl StoredCredential {
    pub fn to_wire(&self) -> Credential {
        Credential {
            id: self.id.clone(),
            label: self.label.clone(),
        }
    }

    fn parse_line(line: &str) -> Option<Self> {
        let (hex_id, rest) = line.split_once(' ')?;
        let id = from_hex(hex_id)?;
        let (pin, label) = rest.split_once(' ')?;
        let pin = match pin {
            "pin" => true,
            "nopin" => false,
            _ => return None,
        };
        Some(StoredCredential {
            id,
            pin,
            label: label.to_string(),
        })
    }

    fn format_line(&self) -> String {
        format!("{} {} {}", to_hex(&self.id), if self.pin { "pin" } else { "nopin" }, self.label)
    }
}

pub fn load_store(path: &std::path::Path) -> io::Result<Vec<StoredCredential>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(text.lines().filter_map(StoredCredential::parse_line).collect())
}

pub fn append_to_store(path: &std::path::Path, cred: &StoredCredential) -> io::Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", cred.format_line())
}

#[cfg(test)]
mod tests {
    use super::StoredCredential;
    use std::path::PathBuf;

    fn write_store(name: &str, lines: &[&str]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("hmac-agent-store-test-{}-{name}", std::process::id()));
        std::fs::write(&path, lines.join("\n")).unwrap();
        path
    }

    #[test]
    fn parses_new_format_with_pin_flag() {
        let path = write_store("new-format", &["aabbccdd pin work-laptop", "11223344 nopin home-nas"]);
        let creds = super::load_store(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].id, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(creds[0].pin);
        assert_eq!(creds[0].label, "work-laptop");
        assert_eq!(creds[1].id, vec![0x11, 0x22, 0x33, 0x44]);
        assert!(!creds[1].pin);
        assert_eq!(creds[1].label, "home-nas");
    }

    #[test]
    fn append_then_load_roundtrips() {
        let path = std::env::temp_dir().join(format!("hmac-agent-store-test-{}-roundtrip", std::process::id()));
        let _ = std::fs::remove_file(&path);

        super::append_to_store(&path, &StoredCredential { id: vec![0xde, 0xad], pin: true, label: "a".to_string() }).unwrap();
        super::append_to_store(&path, &StoredCredential { id: vec![0xbe, 0xef], pin: false, label: "b".to_string() }).unwrap();
        let creds = super::load_store(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(creds.len(), 2);
        assert_eq!((creds[0].id.as_slice(), creds[0].pin, creds[0].label.as_str()), (&[0xde, 0xad][..], true, "a"));
        assert_eq!((creds[1].id.as_slice(), creds[1].pin, creds[1].label.as_str()), (&[0xbe, 0xef][..], false, "b"));
    }
}
