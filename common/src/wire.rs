//! Wire protocol: opcodes, framing, encode/decode. Transport-agnostic.

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

pub const OP_FAILURE: u8 = 0;
pub const OP_LIST: u8 = 1;
pub const OP_LIST_REPLY: u8 = 2;
pub const OP_DERIVE: u8 = 3;
pub const OP_DERIVE_REPLY: u8 = 4;

pub const SALT_LEN: usize = 32;
pub const SECRET_LEN: usize = 32;

/// A FIDO2 credential as sent over the wire, analogous to an `ssh-agent` identity.
#[derive(Debug)]
pub struct Credential {
    pub id: Vec<u8>,
    pub label: String,
}

// Length-prefixed: bodies are raw binary (salts, secrets), so a delimiter
// couldn't distinguish data from framing.
pub fn write_frame<W: Write + ?Sized>(w: &mut W, body: &[u8]) -> io::Result<()> {
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body)
}

pub fn read_frame<R: Read + ?Sized>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    r.read_exact(&mut body)?;
    Ok(body)
}

fn write_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> io::Result<u8> {
        let b = *self.data.get(self.pos).ok_or_else(truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn u32(&mut self) -> io::Result<u32> {
        let bytes: [u8; 4] = self
            .data
            .get(self.pos..self.pos + 4)
            .ok_or_else(truncated)?
            .try_into()
            .unwrap();
        self.pos += 4;
        Ok(u32::from_be_bytes(bytes))
    }

    fn string(&mut self) -> io::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        let s = self.data.get(self.pos..self.pos + len).ok_or_else(truncated)?;
        self.pos += len;
        Ok(s)
    }

    fn bytes(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let s = self.data.get(self.pos..self.pos + n).ok_or_else(truncated)?;
        self.pos += n;
        Ok(s)
    }
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated hmac-agent reply")
}

// ---- LIST -------------------------------------------------------------

pub fn encode_list_request() -> Vec<u8> {
    vec![OP_LIST]
}

pub fn encode_list_reply(creds: &[Credential]) -> Vec<u8> {
    let mut body = vec![OP_LIST_REPLY];
    body.extend_from_slice(&(creds.len() as u32).to_be_bytes());
    for c in creds {
        write_string(&mut body, &c.id);
        write_string(&mut body, c.label.as_bytes());
    }
    body
}

pub fn decode_list_reply(body: &[u8]) -> io::Result<Vec<Credential>> {
    let mut r = Reader::new(body);
    match r.u8()? {
        OP_LIST_REPLY => {}
        OP_FAILURE => return Err(decode_failure(&mut r)?),
        other => return Err(unexpected_reply(other)),
    }
    let count = r.u32()?;
    (0..count)
        .map(|_| {
            let id = r.string()?.to_vec();
            let label = String::from_utf8_lossy(r.string()?).into_owned();
            Ok(Credential { id, label })
        })
        .collect()
}

// ---- DERIVE -------------------------------------------------------------

pub fn encode_derive_request(credential_id: &[u8], salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut body = vec![OP_DERIVE];
    write_string(&mut body, credential_id);
    body.extend_from_slice(salt);
    body
}

pub fn decode_derive_request(body: &[u8]) -> io::Result<(Vec<u8>, [u8; SALT_LEN])> {
    let mut r = Reader::new(body);
    if r.u8()? != OP_DERIVE {
        return Err(unexpected_reply(body[0]));
    }
    let credential_id = r.string()?.to_vec();
    let salt: [u8; SALT_LEN] = r.bytes(SALT_LEN)?.try_into().unwrap();
    Ok((credential_id, salt))
}

pub fn encode_derive_reply(secret: &[u8; SECRET_LEN]) -> Vec<u8> {
    let mut body = vec![OP_DERIVE_REPLY];
    body.extend_from_slice(secret);
    body
}

pub fn decode_derive_reply(body: &[u8]) -> io::Result<Zeroizing<[u8; SECRET_LEN]>> {
    let mut r = Reader::new(body);
    match r.u8()? {
        OP_DERIVE_REPLY => {}
        OP_FAILURE => return Err(decode_failure(&mut r)?),
        other => return Err(unexpected_reply(other)),
    }
    let secret: [u8; SECRET_LEN] = r.bytes(SECRET_LEN)?.try_into().unwrap();
    Ok(Zeroizing::new(secret))
}

// ---- FAILURE -------------------------------------------------------------

pub fn encode_failure(msg: &str) -> Vec<u8> {
    let mut body = vec![OP_FAILURE];
    write_string(&mut body, msg.as_bytes());
    body
}

fn decode_failure(r: &mut Reader) -> io::Result<io::Error> {
    let msg = String::from_utf8_lossy(r.string()?).into_owned();
    Ok(io::Error::other(format!("hmacd: {msg}")))
}

fn unexpected_reply(opcode: u8) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("unexpected hmac-agent opcode {opcode}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip_preserves_body() {
        for body in [b"".as_slice(), b"hello".as_slice()] {
            let mut buf = Vec::new();
            write_frame(&mut buf, body).unwrap();
            let mut cursor = Cursor::new(buf);
            assert_eq!(read_frame(&mut cursor).unwrap(), body);
        }
    }

    #[test]
    fn list_request_is_single_opcode_byte() {
        assert_eq!(encode_list_request(), vec![OP_LIST]);
    }

    #[test]
    fn list_reply_roundtrips_empty_and_multiple() {
        let empty = encode_list_reply(&[]);
        assert!(decode_list_reply(&empty).unwrap().is_empty());

        let creds = [
            Credential { id: vec![0xaa, 0xbb], label: "a".to_string() },
            Credential { id: vec![0xcc], label: "b".to_string() },
        ];
        let decoded = decode_list_reply(&encode_list_reply(&creds)).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].id, vec![0xaa, 0xbb]);
        assert_eq!(decoded[0].label, "a");
        assert_eq!(decoded[1].id, vec![0xcc]);
        assert_eq!(decoded[1].label, "b");
    }

    #[test]
    fn list_reply_surfaces_failure() {
        let err = decode_list_reply(&encode_failure("no device")).unwrap_err();
        assert!(err.to_string().contains("no device"));
    }

    #[test]
    fn list_reply_rejects_unexpected_opcode() {
        let body = encode_derive_reply(&[0u8; SECRET_LEN]);
        assert!(decode_list_reply(&body).is_err());
    }

    #[test]
    fn derive_request_roundtrips() {
        let salt = [7u8; SALT_LEN];
        let body = encode_derive_request(&[1, 2, 3], &salt);
        let (id, decoded_salt) = decode_derive_request(&body).unwrap();
        assert_eq!(id, vec![1, 2, 3]);
        assert_eq!(decoded_salt, salt);
    }

    #[test]
    fn derive_reply_roundtrips() {
        let secret = [9u8; SECRET_LEN];
        let decoded = decode_derive_reply(&encode_derive_reply(&secret)).unwrap();
        assert_eq!(*decoded, secret);
    }

    #[test]
    fn derive_reply_surfaces_failure() {
        let err = decode_derive_reply(&encode_failure("touch declined")).unwrap_err();
        assert!(err.to_string().contains("touch declined"));
    }

    #[test]
    fn truncated_body_is_reported() {
        let salt = [1u8; SALT_LEN];
        let body = encode_derive_request(&[1, 2, 3], &salt);
        let truncated = &body[..body.len() - 1];
        assert_eq!(decode_derive_request(truncated).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}
