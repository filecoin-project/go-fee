# go-fee

Go implementation of the **FEE (Filecoin Encryption Envelope)** — the
standardized encryption container proposed in
[filecoin-project/FIPs discussion #1253](https://github.com/filecoin-project/FIPs/discussions/1253).

FEE decouples encryption metadata from ciphertext so that encrypted data stored
on Filecoin is portable across applications and key-management systems. A FEE
blob is a [COSE](https://www.rfc-editor.org/rfc/rfc9052) (CBOR) envelope —
algorithm identifiers, base nonce, recipient descriptors — immediately followed
by the detached ciphertext:

```
blob = envelope ‖ ciphertext
```

The body cipher is **chunked AES-256-GCM (STREAM)**: the plaintext is split
into fixed-size chunks (256 KiB by default), each sealed independently under a
derived nonce. That gives streaming encryption and decryption with
O(chunk size) memory, plus random-access decryption of any byte range at
O(chunk size) cost. The content-encryption key (CEK) can be wrapped to any
number of recipients — **ECDH-ES+A256KW** to an X25519 public key,
**A256KW** under a pre-shared symmetric key, or managed entirely out of band —
without re-encrypting the data.

The wire format's source of truth is the TypeScript reference implementation,
[`foc-encryption`](https://github.com/Kubuxu/foc-encryption-demo); this repo is
pinned to it by [cross-implementation test vectors](./vectors/README.md).

## Install

```sh
go get github.com/filecoin-project/go-fee
```

Requires Go 1.26+. The package name is `fee` (the module path ends in
`go-fee`), so an explicit import name keeps things readable:

```go
import (
    fee "github.com/filecoin-project/go-fee"
)
```

## Packages

| Package | Purpose |
|---|---|
| [`fee`](.) (root) | Composes the primitives below into a small encrypt/decrypt API for whole objects. Adds no cryptography of its own. |
| [`aesstream`](./aesstream) | The chunked AES-256-GCM STREAM body cipher: streaming `Writer`/`Reader` plus the range-decryption API (`CiphertextRange`, `SpanReader`, `OpenSpan`). |
| [`cose`](./cose) | Just enough of COSE (RFC 9052): `COSE_Encrypt` (tag 96) / `COSE_Encrypt0` (tag 16) with a detached payload, and the `Enc_structure` AAD. |
| [`ecdhkw`](./ecdhkw) | ECDH-ES+A256KW key wrap over X25519 (COSE algorithm −31). |
| [`aeskw`](./aeskw) | RFC 3394 AES Key Wrap / A256KW (COSE algorithm −5). |
| [`vectors`](./vectors) | Cross-implementation test vectors pinning the wire format against the TypeScript reference. |

Most applications only need the root `fee` package.

## Usage

### Encrypt and decrypt to an X25519 recipient

`fee.Encrypt` generates a fresh CEK, wraps it to each recipient, and returns a
streaming reader over `envelope ‖ ciphertext`. The caller **must** read it to
EOF or `Close` it.

```go
package main

import (
    "bytes"
    "crypto/ecdh"
    "crypto/rand"
    "fmt"
    "io"
    "log"

    fee "github.com/filecoin-project/go-fee"
)

func main() {
    // The recipient's X25519 keypair. Normally only the public key is known
    // to the encryptor.
    priv, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    // A kid names the recipient's key. It is opaque bytes to the library —
    // e.g. a DID verification method ID.
    kid := []byte("did:key:z6MkExample#key-1")

    // Encrypt. The returned reader streams envelope‖ciphertext.
    r, err := fee.Encrypt(
        bytes.NewReader([]byte("hello, filecoin")),
        []fee.Recipient{fee.NewECDHESRecipient(kid, priv.PublicKey())},
    )
    if err != nil {
        log.Fatal(err)
    }
    defer r.Close()

    blob, err := io.ReadAll(r)
    if err != nil {
        log.Fatal(err)
    }

    // Decrypt with the matching private key.
    pr, err := fee.Decrypt(bytes.NewReader(blob), fee.NewECDHESUnwrapper(kid, priv))
    if err != nil {
        log.Fatal(err)
    }
    plaintext, err := io.ReadAll(pr)
    if err != nil {
        log.Fatal(err) // a non-EOF read error means: discard the plaintext
    }

    fmt.Printf("%s\n", plaintext)
}
```

### Multiple recipients, mixed algorithms

The same CEK is wrapped to every recipient, so any one of them can recover the
object. Wrap algorithms may be mixed in one envelope; on decrypt the recipient
is selected by kid and the algorithm comes from its COSE header — the caller
never chooses it.

```go
func encryptShared(data []byte, alicePub *ecdh.PublicKey, kek []byte) ([]byte, error) {
    r, err := fee.Encrypt(bytes.NewReader(data), []fee.Recipient{
        // ECDH-ES+A256KW to Alice's X25519 public key.
        fee.NewECDHESRecipient([]byte("did:key:alice#key-1"), alicePub),
        // A256KW under a pre-shared 32-byte key-encryption key.
        fee.NewA256KWRecipient([]byte("did:example:custody#kek-1"), kek),
    })
    if err != nil {
        return nil, err
    }
    defer r.Close()
    return io.ReadAll(r)
}

func decryptWithKEK(blob, kek []byte) ([]byte, error) {
    r, err := fee.Decrypt(bytes.NewReader(blob),
        fee.NewA256KWUnwrapper([]byte("did:example:custody#kek-1"), kek))
    if err != nil {
        return nil, err
    }
    return io.ReadAll(r)
}
```

### Streaming

Both directions stream with O(chunk size) memory: `Encrypt` produces the blob
as the plaintext is read, and `Decrypt` reads only the small envelope header up
front, decrypting the ciphertext on demand. Neither buffers the whole object.

```go
func encryptFile(src, dst string, recipients []fee.Recipient) error {
    in, err := os.Open(src)
    if err != nil {
        return err
    }
    defer in.Close()

    info, err := in.Stat()
    if err != nil {
        return err
    }

    // WithContentLength is optional: it records the chunk count in the
    // envelope (useful to range/seek consumers) and fails the stream if the
    // plaintext turns out to be a different length.
    r, err := fee.Encrypt(in, recipients, fee.WithContentLength(info.Size()))
    if err != nil {
        return err
    }
    defer r.Close()

    out, err := os.Create(dst)
    if err != nil {
        return err
    }
    defer out.Close()

    _, err = io.Copy(out, r)
    return err
}

func decryptFile(src, dst string, u fee.RecipientUnwrapper) error {
    in, err := os.Open(src)
    if err != nil {
        return err
    }
    defer in.Close()

    r, err := fee.Decrypt(in, u)
    if err != nil {
        return err
    }

    out, err := os.Create(dst)
    if err != nil {
        return err
    }
    defer out.Close()

    // Decryption is streaming: each chunk is released as soon as it
    // authenticates. A non-EOF error from the copy means the bytes written so
    // far are incomplete — discard dst.
    _, err = io.Copy(out, r)
    return err
}
```

### External CEK (recipient-less envelopes)

When the CEK is managed out of band — derived deterministically, or issued and
unwrapped by a custody service — use `EncryptWithCEK` / `DecryptWithCEK`. With
no recipients, the envelope is a recipient-less `COSE_Encrypt0` (tag 16).

```go
func roundTripExternalCEK(data []byte) ([]byte, error) {
    cek := make([]byte, 32) // AES-256
    if _, err := rand.Read(cek); err != nil {
        return nil, err
    }

    r, err := fee.EncryptWithCEK(bytes.NewReader(data), cek, nil)
    if err != nil {
        return nil, err
    }
    defer r.Close()
    blob, err := io.ReadAll(r)
    if err != nil {
        return nil, err
    }

    pr, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
    if err != nil {
        return nil, err
    }
    return io.ReadAll(pr)
}
```

> **Warning:** use a distinct CEK per envelope. The only cross-envelope nonce
> separation is the random 7-byte base nonce, which collides at a
> ~2²⁸-envelope birthday bound — and an AES-GCM (key, nonce) reuse is
> catastrophic. `fee.Encrypt` draws a fresh CEK every call; with
> `EncryptWithCEK` this is the caller's obligation.

### Range (seekable) decryption

Because chunks are sealed independently, any plaintext byte range can be
decrypted from a single contiguous slice of the ciphertext — one HTTP range
request against a remote blob. The root `fee` package covers whole-object
decryption only; ranges use the `cose` and `aesstream` packages directly:

```go
import (
    "bytes"
    "errors"

    fee "github.com/filecoin-project/go-fee"
    "github.com/filecoin-project/go-fee/aesstream"
    "github.com/filecoin-project/go-fee/cose"
)

// readRange decrypts plaintext[off : off+length] from a FEE blob without
// decrypting the whole object. cek is the content-encryption key, obtained out
// of band or unwrapped from a recipient entry (see ecdhkw / aeskw).
func readRange(blob, cek []byte, off, length int64) ([]byte, error) {
    const labelChunkSize = int64(-65790)

    // Decode the envelope header: base nonce, chunk size, and the
    // Enc_structure that every chunk is authenticated against.
    env, ciphertext, err := cose.Decode(blob, cose.WithExpectedType(fee.EnvelopeType))
    if err != nil {
        return nil, err
    }
    baseNonce, ok := env.Headers.Unprotected.Bytes(cose.HeaderLabelIV)
    if !ok {
        return nil, errors.New("missing base nonce")
    }
    chunkSize := aesstream.DefaultChunkSize
    if n, ok := env.Headers.Unprotected.Int(labelChunkSize); ok {
        chunkSize = int(n)
    }
    aad, err := env.EncStructure(nil)
    if err != nil {
        return nil, err
    }

    // Which contiguous ciphertext bytes cover the requested plaintext range?
    start, n, err := aesstream.CiphertextRange(int64(len(ciphertext)), chunkSize, off, length)
    if err != nil {
        return nil, err
    }

    // Fetch exactly that span. Against a remote blob this is one range
    // request for bytes [headerLen+start, headerLen+start+n), where
    // headerLen = len(blob) - len(ciphertext).
    span := bytes.NewReader(ciphertext[start : start+n])

    // Decrypt and trim to exactly the requested range. For large ranges,
    // aesstream.NewSpanReader streams instead of buffering.
    return aesstream.OpenSpan(aesstream.Config{
        Key:       cek,
        BaseNonce: baseNonce,
        AAD:       aad,
        ChunkSize: chunkSize,
    }, span, int64(len(ciphertext)), off, length)
}
```

The span is chunk-aligned, so it over-fetches by at most the unused head of the
first chunk and tail of the last (under 2 × chunk size total). For a local
random-access source, wrap it with `io.NewSectionReader(src, start, n)` instead
of a fetch.

## Wire format

`blob = envelope ‖ ciphertext` (COSE detached payload). The envelope is
self-delimiting CBOR; everything after it is the STREAM ciphertext.

```
envelope    = 16([ protected, unprotected, null ])              # no recipients
            | 96([ protected, unprotected, null, recipients ])  # with recipients
protected   = { 1: -65793, 16: "application/vnd.foc-envelope+cose" }
unprotected = { 5: baseNonce(7B), -65790: chunkSize, -65791: chunkCount }
recipient   = [ {1: alg}, {4: kid, ...}, wrappedKey ]           # alg -31 or -5
```

- **Body cipher** — chunked AES-256-GCM-STREAM (private-use COSE algorithm
  −65793). Per-chunk nonce is
  `baseNonce[7] ‖ chunkIndex[4, big-endian] ‖ lastFlag[1]` (`0x01` on the final
  chunk), tag 16 bytes. The STREAM construction (Hoang–Reyhanitabar–Rogaway–
  Vizár, as used by [age](https://age-encryption.org) and Google Tink) enforces
  chunk order and detects truncation and insertion.
- **Body AAD** — the COSE `Enc_structure` over the protected header, identical
  for every chunk, so the algorithm, envelope type and any protected metadata
  are authenticated into the ciphertext.
- **Chunk count** (label −65791) — advisory metadata for range/seek consumers,
  emitted only when the plaintext length is known; not required to decrypt.

## Security notes

- **Streaming decryption releases plaintext before the stream ends.** Each
  chunk is emitted as soon as it authenticates, so a truncated or tampered
  stream can yield valid leading plaintext followed by an error. Treat any
  non-EOF error from a plaintext reader as "discard everything"; only a clean
  `io.EOF` means the object was intact and complete.
- **CEK uniqueness.** `Encrypt` generates a fresh CEK per envelope. With
  `EncryptWithCEK`, reusing a CEK across envelopes erodes the 7-byte base
  nonce's birthday bound (see above).
- **Recipient matching is exact.** `Decrypt` selects the recipient whose kid
  byte-for-byte equals the unwrapper's key id; no unwrap is attempted
  otherwise.
- **Envelope type pinning.** Encrypt writes, and Decrypt requires, the COSE
  `typ` `application/vnd.foc-envelope+cose`, so non-FEE blobs are rejected
  before any key material is touched.

## Specifications and related work

- [FIP discussion #1253 — Filecoin Encryption Envelope](https://github.com/filecoin-project/FIPs/discussions/1253)
- [`foc-encryption`](https://github.com/Kubuxu/foc-encryption-demo) — TypeScript
  reference implementation (wire-format source of truth); see
  [`vectors/`](./vectors/README.md) for the cross-implementation fixtures
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) COSE structure,
  [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053) COSE algorithms,
  [RFC 9596](https://www.rfc-editor.org/rfc/rfc9596) COSE `typ` header,
  [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) CBOR,
  [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394) AES Key Wrap
- [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189)
  — the STREAM construction

## License

Dual-licensed under [Apache 2.0 and MIT](./LICENSE.md).
