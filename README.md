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

Requires Go 1.25+. The package name is `fee` (the module path ends in
`go-fee`), so an explicit import name keeps things readable:

```go
import (
    fee "github.com/filecoin-project/go-fee"
)
```

## Packages

| Package | Purpose |
|---|---|
| [`fee`](.) (root) | Composes the primitives below into a small API: whole-object `Encrypt`/`Decrypt`, byte-range `DecryptRange`, and the cacheable envelope parameters (`BodyDescriptor`) that let a range read skip the header. Adds no cryptography of its own. |
| [`aesstream`](./aesstream) | The chunked AES-256-GCM STREAM body cipher: streaming `Writer`/`Reader` plus the range primitives (`CiphertextRange`, `SpanReader`, `OpenSpan`) that `fee.DecryptRange` is built on. |
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
    r, _, err := fee.Encrypt(
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
    r, _, err := fee.Encrypt(bytes.NewReader(data), []fee.Recipient{
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
    r, _, err := fee.Encrypt(in, recipients, fee.WithContentLength(info.Size()))
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

    r, _, err := fee.EncryptWithCEK(bytes.NewReader(data), cek, nil)
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
decrypted without fetching or decrypting the rest of the object.
`fee.DecryptRange` takes the stored blob as an `io.ReaderAt` plus its exact size,
unwraps the CEK just as `fee.Decrypt` does, and returns a reader over exactly the
requested bytes:

```go
import (
    "fmt"
    "io"
    "net/http"
    "os"
    "strconv"

    fee "github.com/filecoin-project/go-fee"
)

// serveRange answers an HTTP range request straight from an encrypted object.
func serveRange(w http.ResponseWriter, f *os.File, size int64, u fee.RecipientUnwrapper, off, length int64) error {
    r, err := fee.DecryptRange(f, size, u, off, length)
    if err != nil {
        return err // aesstream.ErrRange here means a 416
    }

    // Len is the requested length clamped to the object; Size is the whole
    // object's plaintext size. Both are known before any ciphertext is read.
    if r.Len() == 0 {
        w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", r.Size()))
        w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
        return nil
    }
    w.Header().Set("Content-Length", strconv.FormatInt(r.Len(), 10))
    w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, off+r.Len()-1, r.Size()))
    w.WriteHeader(http.StatusPartialContent)

    _, err = io.Copy(w, r) // decrypts chunk by chunk, O(chunk size) memory
    return err
}
```

Only the envelope header and the ciphertext chunks the range overlaps are read:
one small `ReadAt` at offset 0 for the header, then one `ReadAt` per overlapping
chunk as the result is read. Every chunk read is authenticated, so a tampered
chunk fails rather than yielding corrupt plaintext.

Nothing beyond the header is fetched until the first `Read`, so a caller backed
by a remote store can prefetch the whole span in a single range request:

```go
r, err := fee.DecryptRange(blob, size, unwrapper, off, length)
// ...
spanOff, spanLen := r.CiphertextSpan() // blob-absolute; one range request
```

The span is chunk-aligned, so it over-fetches by at most the unused head of the
first chunk and tail of the last (under 2 × chunk size total).

`fee.PlaintextSize` reports an object's decrypted size from the envelope header
alone — no key material, no ciphertext — which is what a `HEAD` response or a
suffix range (`bytes=-N`) needs. `fee.DecryptRangeWithCEK` is the external-CEK
counterpart of `DecryptRange`. Callers holding raw ciphertext spans rather than a
whole blob can use `aesstream.CiphertextRange` / `SpanReader` / `OpenSpan`
directly.

### Caching the envelope parameters

The envelope is a fixed prefix of every stored object, so a store that keeps its
own metadata beside the blob can record what a range decrypt needs from it and
skip the header read as well. `fee.Encrypt` reports those four values alongside
the reader: envelope length, base nonce, chunk size, and the `Enc_structure` AAD.
They are complete before any plaintext is read, so a writer can store them while
the upload is still streaming:

```go
// d goes alongside the blob's location and size.
r, d, err := fee.Encrypt(plaintext, recipients)
```

`fee.DecryptRangeWithCEK(blob, blobSize, cek, off, length, &d)` then serves a
range with no envelope round trip at all: the only bytes fetched are the
ciphertext chunks the range overlaps. `d.PlaintextSize(blobSize)` answers a
`HEAD` or resolves a suffix range from the stored record alone, reading
nothing.

Every field is non-secret — all four are already in the clear at the front of the
blob — and the CEK is deliberately not among them. Store the AAD rather than the
protected header it contains: the `Enc_structure`'s context string differs between
a `COSE_Encrypt` and a recipient-less `COSE_Encrypt0`, so caching the protected
header alone would need a companion flag recording which form was written. A stale
or corrupted record cannot serve wrong plaintext, since all four values are bound
into every chunk's GCM tag or decide which bytes are read; it fails with
`aesstream.ErrCorrupted` instead. The one check it gives up is `ErrSizeMismatch`:
with no envelope to consult, nothing cross-checks `blobSize` against the declared
chunk count, so a caller that stores the size should compare it with the store's
own before trusting a range.

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
- **Chunking** — a producer writes `ceil(len / chunkSize)` chunks, minimum 1,
  with the remainder in the final chunk; empty input is one empty chunk. A
  decoder also accepts a stream that ends with an empty final chunk, so a
  plaintext of exactly `k × chunkSize` bytes is a valid stream of either `k`
  chunks or `k+1`. Only the ciphertext length distinguishes them
  (`aesstream.ChunkCount`), which is why a declared count must never be checked
  against a count re-derived from the plaintext length.
- **Chunk count** (label −65791) — advisory metadata for range/seek consumers,
  emitted only when the plaintext length is known; not required to decrypt.
- **ECDH-ES key derivation** (alg −31) — HKDF-SHA-256 (RFC 5869) over the X25519
  shared secret, as RFC 9053 §6.3.1 requires, with the §5.2 `COSE_KDF_Context`
  as the info parameter: `AlgorithmID` −5 (A256KW), empty PartyU/PartyV,
  `keyDataLength` 256, and the recipient's serialized protected header
  `h'a101381e'`. JOSE derives ECDH-ES differently (RFC 7518 §4.6 uses the NIST
  SP 800-56A single-step KDF); a KEK derived that way will not unwrap. v0.1.0
  used the COSE Concat-KDF here, so envelopes it encrypted to X25519 recipients
  need decrypting with v0.1.0 and re-encrypting with this version; see the
  [`ecdhkw` package documentation](https://pkg.go.dev/github.com/filecoin-project/go-fee/ecdhkw)
  for the API change that comes with it.

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
  [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394) AES Key Wrap,
  [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) HKDF
- [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189)
  — the STREAM construction

## License

Dual-licensed under [Apache 2.0](./LICENSE-APACHE) OR [MIT](./LICENSE-MIT).
