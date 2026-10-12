//! Shared code between `hmacd`/`hmacd-winapi` and `hmacseal`: wire protocol
//! ([`wire`]), transport ([`endpoint`]), and the on-disk credential store
//! format ([`store`]).

mod endpoint;
mod store;
mod wire;

pub use endpoint::{connect, Duplex, Endpoint, Listener};
pub use store::{append_to_store, load_store, StoredCredential};
pub use wire::*;

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{from_hex, to_hex};

    #[test]
    fn to_hex_formats_lowercase_pairs() {
        assert_eq!(to_hex(&[0xab, 0xcd, 0x00]), "abcd00");
    }

    #[test]
    fn from_hex_parses_valid_input() {
        assert_eq!(from_hex("abcd00"), Some(vec![0xab, 0xcd, 0x00]));
    }

    #[test]
    fn from_hex_rejects_odd_length_or_invalid_digits() {
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
    }
}
