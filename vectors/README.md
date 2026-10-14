# FEE cross-implementation test vectors

Fixed fixtures that pin the **FEE (Filecoin Encryption Envelope)** wire format
across two implementations:

- **Go** — this repo's `cose`, `aesstream`, `ecdhkw`, `aeskw`.
- **TypeScript** — `@filoz/filecoin-encryption-envelope`
  ([`FilOzone/synapse-sdk`](https://github.com/FilOzone/synapse-sdk),
  `packages/filecoin-encryption-envelope`), **pinned** in
  [`pull-synapse-fee.sh`](./pull-synapse-fee.sh) to `6883ba8…` on `master`.

Both follow FIP-1253 with the amendments FilOz's implementation guide adopts:
every body parameter protected, chunk size at label `-1`, an optional
plaintext length at `-65789`, and one encoding per plaintext length (see
[Wire format](#wire-format)).

## What's covered (acceptance criteria)

| Fixture | Direction | Envelope |
|---|---|---|
| `single-chunk-go` | Go seals → TS decrypts | tag 16 (COSE_Encrypt0) |
| `multi-chunk-ts` | TS seals → Go decrypts | tag 16 (COSE_Encrypt0) |
| `multi-recipient-go` | Go seals → TS decrypts body, and unwraps the A256KW recipient | tag 96 (COSE_Encrypt) |
| `multi-chunk-go` | Go seals → TS decrypts (extra multi-chunk coverage) | tag 16 |
| `empty-file-go` | Go seals → TS decrypts | tag 16 |
| `empty-file-ts` | TS seals → Go decrypts | tag 16 |
| `exact-multiple-go` | Go seals → TS decrypts (plaintext is exactly 3 chunks) | tag 16 |
| `kidless-recipient-go` | Go seals → TS decrypts, and unwraps an A256KW recipient that has no kid | tag 96 |
| `kidless-recipient-ts` | TS seals → Go decrypts, and unwraps an A256KW recipient that has no kid | tag 96 |

Four framing cases are covered: a single chunk, a final partial chunk (the
multi-chunk fixtures end mid-chunk), the empty file, and a full final chunk
(`exact-multiple-go`, whose plaintext is exactly 3 chunks). The partial final
chunk and the empty file run in both directions. An empty plaintext encodes as
one empty final chunk, so its whole body is a bare 16-byte tag; `TestVectors`
asserts the ciphertext length for every fixture.

Each `testdata/<name>/` holds `blob.bin` (`envelope‖ciphertext`),
`plaintext.bin`, and `meta.json`.

Both directions are exercised:

- **Go decrypts every fixture** — `go test ./vectors` (`TestVectors`), both
  through this package's own decoder and through `fee.DecryptWithCEK`. For the
  tag-96 fixtures it also *unwraps* each recipient's CEK (ECDH-ES+A256KW over
  X25519, and A256KW) and checks it equals the shared CEK, and decrypts each
  A256KW recipient through `fee.Decrypt`, with a key that has its kid and with
  one that has none.
- **The TypeScript reference reads every fixture** — `pull-synapse-fee.sh`
  drives the pinned reference to decrypt each `blob.bin` whole from the CEK in
  `meta.json`, decrypt a range from the middle of it, and unwrap the CEK from
  each A256KW recipient, with a key that has its kid and with one that has
  none; it also (re)generates the TS-produced fixtures. The
  reference has no ECDH-ES unwrap, so that recipient is checked on the Go side
  only.

## Wire format

`blob = envelope ‖ ciphertext` (detached payload). The COSE envelope is
self-delimiting CBOR; the bytes after it are the STREAM ciphertext.

```
envelope    = 16([ protected, unprotected, null ])              # no recipients
            | 96([ protected, unprotected, null, recipients ])  # with recipients
protected   = { 1: -65793, 16: "application/vnd.filecoin-encryption+cose",
                5: baseNonce(7B), -1: chunkSize, ? -65789: plaintextLength }
unprotected = { }
recipient   = [ h'',        { 1: -5, ? 4: kid }, wrappedKey ]             # A256KW
            | [ { 1: -31 }, { ? 4: kid, -1: ephemeralKey }, wrappedKey ]  # ECDH-ES+A256KW
```

- **Body cipher** — chunked AES-256-GCM-STREAM, alg `-65793`. Per-chunk nonce is
  `baseNonce[7] ‖ chunkIndex[4, big-endian] ‖ lastFlag[1]` (`0x01` on the final
  chunk), tag 16 bytes. Chunk count is `max(1, ceil(plaintextLen / chunkSize))`,
  so an empty plaintext still seals one (empty) final chunk.
- **One encoding per length** — `exact-multiple-go` (exactly 3 chunks of
  plaintext) ends in a full final chunk. A stream that ends in an empty chunk
  after full ones is invalid, so each plaintext length has one ciphertext
  length, and the declared `plaintextLength` is checked exactly against it.
- **Body AAD** — `Enc_structure = [ context, protected, "" ]`, the **same** for
  every chunk. `context` follows the envelope structure per RFC 9052 §5.3:
  `"Encrypt"` for a tag-96 envelope, `"Encrypt0"` for tag-16. AAD interop is
  order-independent: both sides key the AAD off the on-wire raw protected bytes.
- **Recipients** — an A256KW recipient has an empty protected header (`h''`)
  with `alg` unprotected, as RFC 9053 §6.2.1 requires; both implementations
  unwrap it. ECDH-ES+A256KW carries `alg` protected and is unwrapped on the Go
  side only. Because no fixture here pins the
  ECDH key derivation, `TestHKDFPublishedVector` in
  [`ecdhkw/kdf_test.go`](../ecdhkw/kdf_test.go) pins it instead, against the
  COSE-WG example `ecdh-wrap-examples/p256-wrap-128-01`.

## Regenerating

Fixtures are checked in; tests are deterministic (they only read fixed files and
run deterministic decrypt/unwrap). To recreate them:

```bash
# Go-produced fixtures (single-chunk-go, multi-chunk-go, empty-file-go,
# exact-multiple-go, multi-recipient-go, kidless-recipient-go):
FEE_VECTORS_REGEN=1 go test ./vectors -run TestGenerate -v

# Missing TS-produced fixtures (multi-chunk-ts, empty-file-ts,
# kidless-recipient-ts) + verify every
# fixture under the pinned TypeScript reference:
./vectors/pull-synapse-fee.sh
```

The driver writes a TS-produced fixture only when its directory is absent; set
`FEE_VECTORS_REGEN=1` to rewrite one that is already committed.

`pull-synapse-fee.sh` vendors the pinned reference's source into `ts/vendor/`
(gitignored — never committed) with a shallow `git fetch` of the pinned commit,
falling back to fetching the pinned source files from
`raw.githubusercontent.com` where `git` is unavailable. It runs the TypeScript
directly under Node 22.18 or later and installs the reference's dependencies
with npm.

The base nonces (Go's fixed, the reference's random) and the fresh ECDH-ES
ephemeral key in `multi-recipient-go` mean a regenerated blob may differ
byte-for-byte from the committed one while remaining a valid vector; the
committed files are the fixed reference.

## Test key material

All keys (CEKs, the X25519 tenant key, the A256KW KEK, base nonces) are
**non-secret**, derived deterministically from fixed labels, and recorded in
each `meta.json`. They exist only to pin these vectors — never reuse them.
