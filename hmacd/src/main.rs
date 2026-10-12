//! hmacd: daemon holding the physical FIDO2 key, analogous to `ssh-agent`.
//! `register` creates a credential; `serve` answers `hmacseal` requests
//! over a local socket. `--backend` picks how the key is actually driven
//! (see the `backend` module for what's available on this platform).
//!
//! PIN is per-credential (`--pin` on register, when the backend allows
//! it), not global, and selects `credRandomWithUV` vs `credRandomWithoutUV`
//! at derive time -- don't re-register with a different mode, it silently
//! changes the derived secret. The PIN itself is never cached: read fresh
//! per matching derive call into a `Zeroizing<String>`, gone as soon as
//! that call returns.
//!
//! `--listen` is `tcp:<host>:<port>` (default, see `Endpoint`), `pipe:<name>`,
//! or a bare path. TCP is the default because named-pipe/unix-socket
//! forwarding through `ssh -R`/`-L` is broken in Win32-OpenSSH
//! (`w32_getsockopt ERROR: not sock`; PowerShell/Win32-OpenSSH#1564, #2321).
//! `pipe:`/bare path are for same-machine use without `ssh`.

mod backend;

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use backend::Backend;
use hmacseal_common as proto;
use zeroize::Zeroizing;

fn default_store_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_else(|| ".".into());
    Path::new(&home).join(".hmacd-credentials")
}

fn cmd_register(backend: &dyn Backend, rpid: &str, label: &str, use_pin: bool, store: &Path) -> anyhow::Result<()> {
    if backend.pin_required() && !use_pin {
        anyhow::bail!("this backend always requires PIN/UV; pass --pin");
    }

    let (id, hmac_enabled) = backend.make_credential(rpid, label)?;
    if !hmac_enabled {
        eprintln!(
            "warning: authenticator did not confirm hmac-secret support for this credential; \
             derive will likely fail later"
        );
    }

    proto::append_to_store(
        store,
        &proto::StoredCredential {
            id: id.clone(),
            pin: use_pin,
            label: label.to_string(),
        },
    )?;

    println!(
        "registered credential {} as '{}' (rpid={rpid}, {}) in {}",
        proto::to_hex(&id),
        label,
        if use_pin { "pin" } else { "nopin" },
        store.display()
    );
    Ok(())
}

fn handle_connection<S: Read + Write>(stream: &mut S, backend: &dyn Backend, rpid: &str, store: &Path) -> io::Result<()> {
    let body = proto::read_frame(stream)?;
    let reply: Zeroizing<Vec<u8>> = Zeroizing::new(match body.first() {
        Some(&proto::OP_LIST) => {
            let creds = proto::load_store(store)?;
            proto::encode_list_reply(&creds.iter().map(proto::StoredCredential::to_wire).collect::<Vec<_>>())
        }
        Some(&proto::OP_DERIVE) => match proto::decode_derive_request(&body) {
            Ok((credential_id, salt)) => match lookup_and_derive(backend, rpid, &credential_id, salt, store) {
                Ok(secret) => proto::encode_derive_reply(&secret),
                Err(e) => proto::encode_failure(&e.to_string()),
            },
            Err(e) => proto::encode_failure(&e.to_string()),
        },
        _ => proto::encode_failure("unknown request"),
    });
    proto::write_frame(stream, &reply)
}

fn lookup_and_derive(
    backend: &dyn Backend,
    rpid: &str,
    credential_id: &[u8],
    salt: [u8; proto::SALT_LEN],
    store: &Path,
) -> anyhow::Result<Zeroizing<[u8; proto::SECRET_LEN]>> {
    let creds = proto::load_store(store)?;
    let cred = creds
        .iter()
        .find(|c| c.id == credential_id)
        .ok_or_else(|| anyhow::anyhow!("credential not registered with this hmacd"))?;
    // pin picks credRandomWithUV vs credRandomWithoutUV: a backend that always forces UV
    // can't reproduce the nopin secret, it would silently derive the wrong one.
    if backend.pin_required() && !cred.pin {
        anyhow::bail!("credential '{}' was registered without PIN, but this backend always forces PIN/UV and would derive a different secret", cred.label);
    }
    backend.derive(rpid, credential_id, salt, cred.pin)
}

fn cmd_serve(backend: &dyn Backend, rpid: &str, listen_spec: &str, store: &Path) -> anyhow::Result<()> {
    let listener = proto::Listener::bind(listen_spec)?;
    println!("hmacd listening on {listen_spec} (rpid={rpid})");

    for conn in listener.incoming() {
        let mut conn = conn?;
        if let Err(e) = handle_connection(&mut conn, backend, rpid, store) {
            eprintln!("hmacd: connection error: {e}");
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("register") => {
            let mut rpid = "hmacseal.local".to_string();
            let mut label = "default".to_string();
            let mut use_pin = false;
            let mut store = default_store_path();
            let mut backend_name = backend::default_name().to_string();
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--rpid" => rpid = args.next().expect("--rpid requires a value"),
                    "--label" => label = args.next().expect("--label requires a value"),
                    "--pin" => use_pin = true,
                    "--store" => store = PathBuf::from(args.next().expect("--store requires a value")),
                    "--backend" => backend_name = args.next().expect("--backend requires a value"),
                    other => anyhow::bail!("unknown flag: {other}"),
                }
            }
            let backend = backend::by_name(&backend_name)?;
            cmd_register(backend.as_ref(), &rpid, &label, use_pin, &store)
        }
        Some("serve") => {
            let mut rpid = "hmacseal.local".to_string();
            let mut listen = "tcp:127.0.0.1:7623".to_string();
            let mut store = default_store_path();
            let mut backend_name = backend::default_name().to_string();
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--rpid" => rpid = args.next().expect("--rpid requires a value"),
                    "--listen" => listen = args.next().expect("--listen requires a value"),
                    "--store" => store = PathBuf::from(args.next().expect("--store requires a value")),
                    "--backend" => backend_name = args.next().expect("--backend requires a value"),
                    other => anyhow::bail!("unknown flag: {other}"),
                }
            }
            let backend = backend::by_name(&backend_name)?;
            cmd_serve(backend.as_ref(), &rpid, &listen, &store)
        }
        _ => {
            eprintln!("usage: hmacd register --label <name> [--pin] [--rpid <rpid>] [--store <path>] [--backend <name>]");
            eprintln!("       hmacd serve [--listen <spec>] [--rpid <rpid>] [--store <path>] [--backend <name>]");
            eprintln!("       --backend defaults to '{}' on this platform (available: {})", backend::default_name(), backend::available_names());
            eprintln!("       --listen is tcp:<host>:<port> (default), pipe:<name>, or a bare local socket path");
            eprintln!("       --pin on register ties that credential to PIN-protected derives,");
            eprintln!("       prompted fresh (never cached) on each matching derive call");
            std::process::exit(1);
        }
    }
}
