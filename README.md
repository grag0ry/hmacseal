# hmacseal

Encrypt data at rest, sealed to your YubiKey via FIDO2 hmac-secret.

## How it works

`hmacd` runs on the machine with the physical key. It asks the key to
compute a FIDO2 `hmac-secret` extension value for a random salt.

`hmacseal` is a thin client. It talks to `hmacd` over a local socket and
derives an AES-256-GCM key from the returned secret with HKDF. If the
key lives on a different machine, forward the socket first with
`ssh -R` or `-L`.

`hmac-secret` is deterministic for a given credential and salt. The same
key reproduces it later to decrypt. The private key material never
leaves the device.

## Usage

On the machine with the key:

```
hmacd register --label work-laptop
hmacd serve
```

Wherever you encrypt or decrypt, forward hmacd's socket there first:

```
hmacseal identities
hmacseal encrypt [--credential <label-or-hex>] < plaintext > sealed.bin
hmacseal decrypt < sealed.bin > plaintext
```

`$HMACSEAL_CREDENTIAL` sets the default `--credential`. `$HMAC_AGENT_SOCKET`
picks how `hmacseal` reaches `hmacd`: `tcp:<host>:<port>`, `pipe:<name>`
(Windows), or a local socket path.

PIN is optional. You set it per credential at `register` time with
`--pin`.

On Windows, `hmacd` can drive the key two ways. The default,
`--backend winapi`, uses `webauthn.dll`. It needs no admin rights, but
every derive pops the security key consent dialog, and PIN/UV is always
forced. `--backend ctap` drives the key over raw HID instead. It needs
admin rights, and PIN stays optional.

## Install

Download a prebuilt binary from the [Releases](../../releases) page, or
build from source:

```
cargo build --release
```

## Disclaimer

This is a personal hobby project, built for my own use and shared as-is.
It comes with no warranty and no security guarantee of any kind. Review
the code yourself before you trust it with anything sensitive.

## License

BSD-2-Clause, see [LICENSE](LICENSE).
