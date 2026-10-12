mod client;
mod crypto;

use std::io::{self, Read, Write};
use std::process::ExitCode;

use client::Credential;
use hmacseal_common as proto;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn fingerprint(credential_id: &[u8]) -> [u8; 32] {
    Sha256::digest(credential_id).into()
}

fn cmd_identities() -> io::Result<()> {
    let path = client::socket_path();
    for c in client::list_credentials(&path)? {
        println!("{} {}", proto::to_hex(&c.id), c.label);
    }
    Ok(())
}

fn select_credential(path: &str, requested: Option<&str>) -> io::Result<Credential> {
    let credentials = client::list_credentials(path)?;
    match requested {
        Some(want) => credentials
            .into_iter()
            .find(|c| c.label == want || proto::to_hex(&c.id) == want)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("hmacd has no credential '{want}'"))),
        None => match credentials.len() {
            0 => Err(io::Error::new(io::ErrorKind::NotFound, "hmacd has no credentials registered (run hmacd register first)")),
            1 => Ok(credentials.into_iter().next().unwrap()),
            _ => {
                let list = credentials
                    .iter()
                    .map(|c| format!("  {} {}", proto::to_hex(&c.id), c.label))
                    .collect::<Vec<_>>()
                    .join("\n");
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("multiple credentials registered, pick one with --credential:\n{list}"),
                ))
            }
        },
    }
}

fn cmd_encrypt(requested: Option<&str>) -> io::Result<()> {
    let path = client::socket_path();
    let credential = select_credential(&path, requested)?;

    let mut plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    io::stdin().read_to_end(&mut plaintext)?;

    let mut salt = [0u8; crypto::SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| io::Error::other(e.to_string()))?;

    let secret = client::derive(&path, &credential.id, &salt)?;
    let ciphertext = crypto::seal(&plaintext, &secret);

    let mut blob = Vec::new();
    crypto::Header {
        fingerprint: fingerprint(&credential.id),
        salt,
    }
    .write(&mut blob);
    blob.extend_from_slice(&ciphertext);

    io::stdout().write_all(&blob)
}

fn cmd_decrypt() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let (header, ciphertext) = crypto::Header::parse(&input)?;

    let path = client::socket_path();
    let credential = client::list_credentials(&path)?
        .into_iter()
        .find(|c| fingerprint(&c.id) == header.fingerprint)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "required credential is not known to hmacd"))?;

    let secret = client::derive(&path, &credential.id, &header.salt)?;
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(crypto::unseal(ciphertext, &secret)?);
    io::stdout().write_all(&plaintext)
}

fn parse_credential_flag(mut args: impl Iterator<Item = String>) -> io::Result<Option<String>> {
    match args.next().as_deref() {
        None => Ok(None),
        Some("--credential") => Ok(Some(
            args.next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--credential requires a value"))?,
        )),
        Some(other) => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown argument: {other}"))),
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let result = match args.next().as_deref() {
        Some("identities") => cmd_identities(),
        Some("encrypt") => parse_credential_flag(args)
            .map(|c| c.or_else(|| std::env::var("HMACSEAL_CREDENTIAL").ok()))
            .and_then(|c| cmd_encrypt(c.as_deref())),
        Some("decrypt") => cmd_decrypt(),
        _ => {
            eprintln!("usage: hmacseal encrypt [--credential <label-or-hex>] | decrypt | identities");
            eprintln!("       --credential defaults to $HMACSEAL_CREDENTIAL if set");
            eprintln!("       $HMAC_AGENT_SOCKET is tcp:<host>:<port>, pipe:<name>, or a bare local");
            eprintln!("       socket path (default: \\\\.\\pipe\\hmacd on Windows, /tmp/hmacd.sock elsewhere)");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hmacseal: {e}");
            ExitCode::FAILURE
        }
    }
}
