//! Transport spec and connect/listen plumbing shared by `hmacd`/
//! `hmacd-winapi` (`--listen`) and `hmacseal` (`$HMAC_AGENT_SOCKET`).

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

use interprocess::local_socket::{prelude::*, GenericFilePath, GenericNamespaced, ListenerOptions, Stream};

/// `tcp:<host>:<port>` (recommended for anything crossing `ssh`, see
/// hmacd-winapi's docs), `pipe:<name>` (Windows named pipe), or a bare
/// local socket path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Tcp(String),
    Pipe(String),
    Local(String),
}

impl Endpoint {
    pub fn parse(spec: &str) -> Self {
        if let Some(rest) = spec.strip_prefix("tcp:") {
            Endpoint::Tcp(rest.to_string())
        } else if let Some(rest) = spec.strip_prefix("pipe:") {
            Endpoint::Pipe(rest.to_string())
        } else {
            Endpoint::Local(spec.to_string())
        }
    }
}

pub trait Duplex: Read + Write {}
impl<T: Read + Write> Duplex for T {}

pub fn connect(spec: &str) -> io::Result<Box<dyn Duplex>> {
    let fail = |e: io::Error| io::Error::new(e.kind(), format!("can't connect to {spec} ({e})"));
    match Endpoint::parse(spec) {
        Endpoint::Tcp(addr) => Ok(Box::new(TcpStream::connect(&addr).map_err(fail)?)),
        Endpoint::Pipe(name) => {
            let ns_name = name.to_ns_name::<GenericNamespaced>()?;
            Ok(Box::new(Stream::connect(ns_name).map_err(fail)?))
        }
        Endpoint::Local(path) => {
            let fs_name = path.to_fs_name::<GenericFilePath>()?;
            Ok(Box::new(Stream::connect(fs_name).map_err(fail)?))
        }
    }
}

pub enum Listener {
    Tcp(TcpListener),
    Local(interprocess::local_socket::Listener),
}

impl Listener {
    pub fn bind(spec: &str) -> io::Result<Self> {
        match Endpoint::parse(spec) {
            Endpoint::Tcp(addr) => Ok(Listener::Tcp(TcpListener::bind(&addr)?)),
            Endpoint::Pipe(name) => {
                let ns_name = name.to_ns_name::<GenericNamespaced>()?;
                Ok(Listener::Local(ListenerOptions::new().name(ns_name).create_sync()?))
            }
            Endpoint::Local(path) => {
                let fs_name = path.to_fs_name::<GenericFilePath>()?;
                Ok(Listener::Local(ListenerOptions::new().name(fs_name).create_sync()?))
            }
        }
    }

    pub fn incoming(&self) -> Box<dyn Iterator<Item = io::Result<Box<dyn Duplex>>> + '_> {
        match self {
            Listener::Tcp(l) => Box::new(l.incoming().map(|r| r.map(|s| Box::new(s) as Box<dyn Duplex>))),
            Listener::Local(l) => Box::new(l.incoming().map(|r| r.map(|s| Box::new(s) as Box<dyn Duplex>))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{connect, Endpoint, Listener};
    use std::io::{Read, Write};

    #[test]
    fn parses_tcp() {
        assert_eq!(Endpoint::parse("tcp:127.0.0.1:7623"), Endpoint::Tcp("127.0.0.1:7623".to_string()));
    }

    #[test]
    fn parses_pipe() {
        assert_eq!(Endpoint::parse("pipe:hmacd"), Endpoint::Pipe("hmacd".to_string()));
    }

    #[test]
    fn falls_back_to_local_path() {
        assert_eq!(Endpoint::parse("/tmp/hmacd.sock"), Endpoint::Local("/tmp/hmacd.sock".to_string()));
        assert_eq!(Endpoint::parse(r"\\.\pipe\hmacd"), Endpoint::Local(r"\\.\pipe\hmacd".to_string()));
    }

    #[test]
    fn named_endpoint_roundtrips_bytes() {
        let spec = format!("pipe:hmac-agent-endpoint-test-{}", std::process::id());

        let listener = Listener::bind(&spec).unwrap();
        let server = std::thread::spawn(move || {
            let mut conn = listener.incoming().next().unwrap().unwrap();
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).unwrap();
            conn.write_all(&buf).unwrap();
        });

        let mut client = connect(&spec).unwrap();
        client.write_all(b"hello").unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        server.join().unwrap();
    }
}
