// Package fee composes the FEE (Filecoin Encryption Envelope) primitives
// into a single, small public API for encrypting and decrypting whole objects.
//
// The cryptographic building blocks each live in a sub-package and are
// deliberately unaware of one another:
//
//   - fee/cose      — the COSE_Encrypt (tag 96) / COSE_Encrypt0 (tag 16)
//     envelope with a detached payload, and the Enc_structure that
//     authenticates the protected header as AEAD additional data (AAD).
//   - fee/aesstream — the chunked AES-256-GCM-STREAM body cipher: it seals the
//     plaintext under a per-object content-encryption key (CEK) and a random
//     base nonce.
//   - fee/ecdhkw    — the ECDH-ES+A256KW key wrap over X25519: it encrypts the
//     CEK to a recipient's X25519 public key.
//   - fee/aeskw     — RFC 3394 AES Key Wrap (A256KW): it wraps the CEK directly
//     under a symmetric key-encryption key (KEK).
//
// This package sequences them so callers do not have to. [Encrypt] generates a
// fresh CEK, seals the plaintext with the STREAM body cipher, wraps the CEK to
// each [Recipient], and encodes the COSE envelope; [Decrypt] reverses the
// process, locating the recipient that a [RecipientUnwrapper] holds the key for,
// recovering the CEK, and streaming out the plaintext.
//
// # Recipients and content-encryption keys
//
// The body is sealed under a single content-encryption key (CEK). Two concerns
// are independent: which algorithm wraps the CEK, and how the CEK reaches the
// decryptor.
//
// A CEK can be carried in the envelope as one or more COSE_Recipient entries
// (a COSE_Encrypt, tag 96), each keyed by a caller-supplied key id (kid —
// opaque to this package, e.g. a DID verification method ID). Two wrap
// algorithms are available and may be mixed in one envelope; on decrypt the
// caller never selects the algorithm, the recipient's COSE header does:
//
//   - ECDH-ES+A256KW to an X25519 public key: [NewECDHESRecipient] /
//     [NewECDHESUnwrapper].
//   - A256KW under a symmetric KEK: [NewA256KWRecipient] / [NewA256KWUnwrapper].
//
// Alternatively the CEK can be managed out of band — generated or unwrapped by a
// custody service and handed to this package directly. [EncryptWithCEK] seals
// under a caller-provided CEK, and with no recipients it emits a recipient-less
// COSE_Encrypt0 (tag 16); [DecryptWithCEK] decrypts with a caller-provided CEK,
// accepting either tag and ignoring any recipients.
//
// # Wire format
//
// The blob is the detached-payload convention: the encoded COSE envelope
// immediately followed by the STREAM ciphertext (envelope || ciphertext). The
// body protected header carries every FEE content parameter, so the envelope AAD
// authenticates all of them: the envelope type ([EnvelopeType]), the body
// algorithm (chunked AES-256-GCM-STREAM), the STREAM base nonce in the COSE iv
// parameter, the plaintext chunk size and — when the plaintext length is known —
// the plaintext length. The body unprotected header is empty. These conventions
// follow FIP-1253 and the FEE cross-implementation vectors (see fee/vectors).
//
// # Streaming
//
// Both directions stream with O(chunk size) memory. [Encrypt] returns an
// io.ReadCloser over envelope||ciphertext, produced as the plaintext is read;
// [Decrypt] reads only the (small) envelope header up front and streams the
// detached ciphertext from its source on demand. Neither buffers the whole
// object.
//
// # Byte ranges
//
// [DecryptRange] serves one plaintext byte range of a stored blob without
// fetching or decrypting the rest of it: it decodes the envelope header, recovers
// the CEK exactly as [Decrypt] does, and reads only the ciphertext chunks the
// range overlaps. [DecryptRangeWithCEK] is its external-CEK counterpart, and
// [PlaintextSize] answers an object's decrypted size from the header alone, with
// no key material. Callers that hold raw ciphertext spans rather than a blob can
// use the underlying primitives in fee/aesstream directly.
//
// A store that keeps metadata beside its blobs can drop the header read too.
// [Encrypt] reports the envelope parameters a range decrypt needs as a
// [BodyDescriptor]; persisting those and passing them to
// [DecryptRangeWithCEK] as its desc argument serves a range with no envelope
// round trip at all, and [BodyDescriptor.PlaintextSize] answers a HEAD from
// the same record.
//
// # Scope
//
// This package sequences the primitives and adds no cryptography of its own.
package fee

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/filecoin-project/go-fee/aesstream"
	"github.com/filecoin-project/go-fee/cose"
)

// EnvelopeType is the COSE "typ" (RFC 9596, header label 16) that every FEE
// envelope is pinned to. [Encrypt] writes it into the body protected header and
// [Decrypt] requires it on decode, so a blob that is not a FEE envelope is
// rejected before any key material is touched. Its value is the one FIP-1253
// defines.
const EnvelopeType = "application/vnd.filecoin-encryption+cose"

// algChunkedAES256GCMStream is the FEE private-use COSE algorithm id for the
// chunked AES-256-GCM-STREAM body cipher (fee/aesstream). It is the body
// protected header's alg value; [Decrypt] checks it so an envelope sealed with a
// different body cipher is refused rather than mis-decrypted.
const algChunkedAES256GCMStream int64 = -65793

// FEE body header labels. All of them belong in the body protected header,
// where every chunk's AAD authenticates them; an envelope that carries any of
// them, or the iv, in its unprotected header is malformed.
const (
	// labelChunkSize holds the STREAM plaintext chunk size, in bytes. It is
	// required. FIP-1253 places it at -1, a label whose meaning COSE scopes to
	// the algorithm (RFC 9052 §3.1), here chunked AES-256-GCM-STREAM.
	labelChunkSize int64 = -1
	// labelPlaintextLength holds the exact plaintext length, in bytes. It is
	// emitted only when the length is known before encryption
	// ([WithContentLength]) and is not required to decrypt. Each plaintext
	// length has one valid ciphertext length, so a reader checks it against
	// the blob size and detects any truncation, even a range that never reads
	// the final chunk.
	labelPlaintextLength int64 = -65789
	// labelAppMetadata holds application metadata: a string-keyed map that
	// this package carries authenticated but neither writes nor interprets.
	labelAppMetadata int64 = -65792
)

// bodyContentLabels are the body header parameters FEE requires to be
// protected; [validateBodyParams] rejects any of them in the unprotected
// header.
var bodyContentLabels = []int64{
	cose.HeaderLabelAlg, cose.HeaderLabelType, cose.HeaderLabelIV,
	labelChunkSize, labelPlaintextLength, labelAppMetadata,
}

// bodyUnderstoodLabels are the body header parameters this package knows how
// to process, so an envelope may list them as critical (crit, label 2).
var bodyUnderstoodLabels = map[int64]bool{
	cose.HeaderLabelAlg: true, cose.HeaderLabelCrit: true, cose.HeaderLabelContentType: true,
	cose.HeaderLabelIV: true, cose.HeaderLabelType: true,
	labelChunkSize: true, labelPlaintextLength: true, labelAppMetadata: true,
}

// envelopeDecodeOptions are the cose decode rules every FEE envelope is held
// to: the FEE envelope type, and one accepted CBOR encoding (definite lengths,
// shortest-form arguments, no floats).
var envelopeDecodeOptions = []cose.DecodeOption{
	cose.WithExpectedType(EnvelopeType),
	cose.WithStrictEncoding(),
}

// checkCrit processes a header pair's crit parameter (label 2, RFC 9052 §3.1):
// it must be protected, it must be a non-empty array of labels, and every label
// it names must be one the caller understands. An envelope that marks a
// parameter critical which this package cannot process is malformed rather
// than read with that parameter ignored.
func checkCrit(h cose.Headers, understood map[int64]bool) error {
	if h.Unprotected.Has(cose.HeaderLabelCrit) {
		return fmt.Errorf("%w: crit must be protected", ErrMalformedEnvelope)
	}
	v, ok := h.Protected.Get(cose.HeaderLabelCrit)
	if !ok {
		return nil
	}
	labels, ok := v.([]any)
	if !ok || len(labels) == 0 {
		return fmt.Errorf("%w: crit must be a non-empty array of labels", ErrMalformedEnvelope)
	}
	for _, l := range labels {
		n, ok := l.(int64)
		if !ok || !understood[n] {
			return fmt.Errorf("%w: crit names header %v, which this package does not understand", ErrMalformedEnvelope, l)
		}
	}
	return nil
}

// Sentinel errors. Decrypt failures that originate in a sub-package are wrapped
// rather than replaced, so errors.Is still matches the sub-package sentinel
// (e.g. cose.ErrMalformed, aeskw.ErrIntegrity, aesstream.ErrCorrupted) in
// addition to the fee-level classification here.
var (
	// ErrNoRecipients means Encrypt was called with no recipients. Encrypt
	// wraps a freshly generated CEK, so it needs at least one recipient to be
	// recoverable; use EncryptWithCEK for a recipient-less (external-CEK) envelope.
	ErrNoRecipients = errors.New("fee: at least one recipient is required")

	// ErrNoMatchingRecipient means no recipient entry in the envelope carries a
	// kid equal to the unwrapper's key id, so there is no wrapped CEK for this
	// unwrapper to recover.
	ErrNoMatchingRecipient = errors.New("fee: no envelope recipient matches the unwrapper's key id")

	// ErrNoRecipientsInEnvelope means Decrypt was given a recipient-less
	// COSE_Encrypt0 (tag 16) envelope; recover it with DecryptWithCEK instead.
	ErrNoRecipientsInEnvelope = errors.New("fee: envelope carries no recipients; use DecryptWithCEK")

	// ErrUnsupportedBodyAlg means the envelope's body algorithm header is absent
	// or is not the FEE chunked AES-256-GCM-STREAM cipher.
	ErrUnsupportedBodyAlg = errors.New("fee: unsupported body algorithm")

	// ErrUnsupportedRecipientAlg means a matched recipient's key-wrap algorithm
	// header does not match the unwrapper that was asked to recover it (e.g. an
	// ECDH-ES unwrapper matched against an A256KW recipient).
	ErrUnsupportedRecipientAlg = errors.New("fee: unsupported recipient key-wrap algorithm")

	// ErrMalformedEnvelope means a required body header was missing or had the
	// wrong type, or a declared parameter was out of range.
	ErrMalformedEnvelope = errors.New("fee: malformed FEE envelope")

	// ErrNilUnwrapper means Decrypt was given a nil RecipientUnwrapper.
	ErrNilUnwrapper = errors.New("fee: nil recipient unwrapper")

	// ErrInvalidCEK means a caller-provided content-encryption key (see
	// EncryptWithCEK / DecryptWithCEK) was not the required AES-256 key length.
	ErrInvalidCEK = errors.New("fee: content-encryption key must be 32 bytes")

	// ErrContentLengthMismatch means the plaintext length declared via
	// WithContentLength did not match the number of bytes actually read; it
	// surfaces from the returned reader, and the envelope's declared length
	// (already written) is not to be trusted.
	ErrContentLengthMismatch = errors.New("fee: plaintext length did not match the declared content length")
)

// encryptConfig holds the resolved, optional Encrypt parameters.
type encryptConfig struct {
	chunkSize     int
	contentLength int64 // < 0 means unknown (plaintext length omitted)
}

// EncryptOption configures [Encrypt] and [EncryptWithCEK].
type EncryptOption func(*encryptConfig)

// WithChunkSize sets the STREAM plaintext chunk size, in bytes. A value of 0
// (or an unset option) selects [aesstream.DefaultChunkSize] (256 KiB); any other
// value must be in [aesstream.MinChunkSize, aesstream.MaxChunkSize]. The chosen
// size is recorded in the envelope, so [Decrypt] recovers it.
func WithChunkSize(n int) EncryptOption {
	return func(c *encryptConfig) { c.chunkSize = n }
}

// WithContentLength declares the total plaintext length in bytes. When set to a
// non-negative value, the envelope records it in the protected header, which
// lets a reader detect a truncated blob from its size alone, and the returned
// reader fails with [ErrContentLengthMismatch] if the plaintext turns out to be
// a different length.
//
// A negative n is treated as "unknown", identical to not calling this option: a
// caller propagating an unknown HTTP Content-Length as -1 gets the unset
// behavior (no recorded length, no mismatch check) rather than an error. When
// unknown, the length is omitted — the object still decrypts, and range
// decryption derives the geometry from the ciphertext length alone.
func WithContentLength(n int64) EncryptOption {
	return func(c *encryptConfig) { c.contentLength = n }
}

// Encrypt seals plaintext into a FEE envelope (a COSE_Encrypt, tag 96) addressed
// to recipients and returns a reader over the wire blob: the encoded envelope
// immediately followed by the detached STREAM ciphertext (envelope||ciphertext).
//
// It generates a fresh content-encryption key (CEK) and base nonce, wraps the
// CEK to each recipient, and streams the plaintext through the chunked
// AES-256-GCM-STREAM body cipher, so both plaintext and ciphertext flow with
// O(chunk size) memory. The same CEK is wrapped to every recipient, so any one
// of them can recover the object. recipients must be non-empty (the generated
// CEK would otherwise be unrecoverable); a nil or invalid recipient is reported
// before any plaintext is read. To seal under a CEK you already hold, or a
// recipient-less envelope, use [EncryptWithCEK].
//
// The plaintext is pulled through the body cipher as the returned reader is
// read (no goroutine or pipe stands between them), and the reader implements
// io.WriterTo, so an io.Copy from it writes each sealed chunk whole. A
// plaintext read failure surfaces as a non-EOF error from the reader's Read,
// and ends the stream before its final chunk. Close releases the reader; a
// caller that abandons a partial read should still Close it.
//
// The second result is the envelope parameters a later range decrypt needs, for a
// caller that wants to cache them rather than re-read the header; see
// [BodyDescriptor]. It is complete on return, before any plaintext is read, so a
// writer can record it while the upload is still streaming. Callers with no use
// for it discard it.
func Encrypt(plaintext io.Reader, recipients []Recipient, opts ...EncryptOption) (io.ReadCloser, BodyDescriptor, error) {
	if len(recipients) == 0 {
		return nil, BodyDescriptor{}, ErrNoRecipients
	}
	cek := make([]byte, aesstream.KeySize)
	if _, err := rand.Read(cek); err != nil {
		return nil, BodyDescriptor{}, fmt.Errorf("fee: generating content-encryption key: %w", err)
	}
	// encryptStream copies the CEK into the body cipher and wraps it to the
	// recipients (synchronously, before it returns), so our generated copy can be
	// wiped once it returns — on every path.
	defer zero(cek)
	return encryptStream(plaintext, cek, recipients, opts...)
}

// EncryptWithCEK is [Encrypt] with a caller-provided content-encryption key
// instead of a freshly generated one — for when the CEK is managed out of band
// (derived deterministically, or issued by a custody service). cek must be 32
// bytes (AES-256).
//
// With one or more recipients it produces a COSE_Encrypt (tag 96) that also
// carries the wrapped CEK; with no recipients it produces a recipient-less
// COSE_Encrypt0 (tag 16). Pair it with [DecryptWithCEK] to recover without an
// in-envelope unwrap.
//
// The caller MUST use a distinct cek per envelope (or keep reuse far below the
// birthday bound below). Unlike [Encrypt], which draws a fresh CEK each call,
// this seals under a caller-supplied key — so the only cross-envelope nonce
// separation is the random base nonce, which is [aesstream.BaseNonceSize] (7)
// bytes. Under a reused CEK, two envelopes drawing the same base nonce reuse an
// AES-GCM (key, nonce) pair, which is catastrophic (keystream reuse + tag
// forgery). A 7-byte random nonce collides at a ~2^28-envelope birthday bound,
// so sealing on the order of 2^30 objects under one CEK makes a collision
// essentially certain. The wire format is fixed by the FEE spec, so this is a
// caller obligation, not something this package can enforce.
//
// The caller retains ownership of cek: it is copied into the body cipher (and
// wrapped to any recipients) but neither retained nor wiped by this call.
//
// As with [Encrypt], the second result carries the envelope parameters a later
// range decrypt needs; see [BodyDescriptor]. They are reported for a
// recipient-less COSE_Encrypt0 exactly as for a COSE_Encrypt.
func EncryptWithCEK(plaintext io.Reader, cek []byte, recipients []Recipient, opts ...EncryptOption) (io.ReadCloser, BodyDescriptor, error) {
	if err := checkCEK(cek); err != nil {
		return nil, BodyDescriptor{}, err
	}
	return encryptStream(plaintext, cek, recipients, opts...)
}

// encryptStream is the shared core of Encrypt and EncryptWithCEK: it seals
// plaintext under cek and returns a streaming reader over envelope||ciphertext.
// With no recipients it emits a COSE_Encrypt0 (tag 16); otherwise a COSE_Encrypt
// (tag 96). It does not modify or wipe cek.
//
// It also does not retain cek past its own return: the recipient wraps and the
// aesstream.NewEncryptReader that internalizes the CEK (into a GCM AEAD) both
// run synchronously before encryptStream returns, so a caller may wipe cek as
// soon as it returns — even though the returned reader has not been read. The
// body cipher works from its internalized key, never from the cek slice.
func encryptStream(plaintext io.Reader, cek []byte, recipients []Recipient, opts ...EncryptOption) (io.ReadCloser, BodyDescriptor, error) {
	if plaintext == nil {
		return nil, BodyDescriptor{}, errors.New("fee: nil plaintext reader")
	}
	for i, r := range recipients {
		if r == nil {
			return nil, BodyDescriptor{}, fmt.Errorf("fee: recipient %d is nil", i)
		}
		if err := r.validate(); err != nil {
			return nil, BodyDescriptor{}, fmt.Errorf("fee: recipient %d: %w", i, err)
		}
	}

	cfg := encryptConfig{chunkSize: aesstream.DefaultChunkSize, contentLength: -1}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.chunkSize == 0 {
		cfg.chunkSize = aesstream.DefaultChunkSize
	}
	if cfg.chunkSize < aesstream.MinChunkSize || cfg.chunkSize > aesstream.MaxChunkSize {
		// An out-of-range WithChunkSize is an invalid argument on the encrypt
		// path — no envelope exists yet — so it is not ErrMalformedEnvelope (a
		// decode-side classification). Surface aesstream.ErrChunkSize, the same
		// sentinel aesstream.NewWriter would return for this size.
		return nil, BodyDescriptor{}, fmt.Errorf("fee: chunk size %d: %w", cfg.chunkSize, aesstream.ErrChunkSize)
	}

	baseNonce, err := aesstream.NewBaseNonce()
	if err != nil {
		return nil, BodyDescriptor{}, fmt.Errorf("fee: generating base nonce: %w", err)
	}

	// The body header is fixed before encryption, and every parameter in it is
	// protected (authenticated through the Enc_structure AAD): the algorithm,
	// envelope type, base nonce, chunk size and, when the length is known, the
	// plaintext length. The unprotected header is empty.
	protected := cose.Header{}.
		Set(cose.HeaderLabelAlg, algChunkedAES256GCMStream).
		Set(cose.HeaderLabelType, EnvelopeType).
		Set(cose.HeaderLabelIV, baseNonce).
		Set(labelChunkSize, int64(cfg.chunkSize))
	if cfg.contentLength >= 0 {
		protected.Set(labelPlaintextLength, cfg.contentLength)
	}
	headers := cose.Headers{
		Protected:   protected,
		Unprotected: cose.Header{},
	}

	// Wrap the CEK to each recipient (none → a recipient-less envelope). All the
	// fallible header work happens here, before the pipe is created, so an error
	// returns before the pipe exists and can never orphan a PipeReader/PipeWriter
	// pair.
	entries := make([]*cose.Recipient, len(recipients))
	for i, r := range recipients {
		entry, werr := r.wrap(cek)
		if werr != nil {
			return nil, BodyDescriptor{}, werr
		}
		entries[i] = entry
	}

	// One envelope drives both the AAD and the encoded header. Recipient presence
	// alone selects the form — a COSE_Encrypt (tag 96) when present, a
	// recipient-less COSE_Encrypt0 (tag 16) when not — and the Enc_structure
	// context tracks it. The AAD binds the protected header into every STREAM
	// chunk.
	env := &cose.Envelope{Headers: headers, Recipients: entries}
	aad, err := env.EncStructure(nil)
	if err != nil {
		return nil, BodyDescriptor{}, fmt.Errorf("fee: building envelope AAD: %w", err)
	}
	header, err := env.Encode()
	if err != nil {
		return nil, BodyDescriptor{}, fmt.Errorf("fee: encoding envelope: %w", err)
	}

	// Every fallible step above has succeeded, so the body cipher can be
	// built; NewEncryptReader's own validation (key, base nonce, chunk size) is
	// already satisfied here. The cipher pulls plaintext as the returned reader
	// is read: no goroutine, no pipe, and each sealed chunk reaches the consumer
	// in one piece (see aesstream.EncryptReader).
	src := plaintext
	if cfg.contentLength >= 0 {
		src = &lengthCheckedReader{r: plaintext, declared: cfg.contentLength}
	}
	body, err := aesstream.NewEncryptReader(src, aesstream.Config{
		Key:       cek,
		BaseNonce: baseNonce,
		AAD:       aad,
		ChunkSize: cfg.chunkSize,
	})
	if err != nil {
		return nil, BodyDescriptor{}, fmt.Errorf("fee: initializing body cipher: %w", err)
	}

	// Every value the descriptor reports is fixed above, before any plaintext is
	// read, so a caller can record it while the upload is still streaming. The
	// clone keeps it independent of the buffers the cipher and the encoded header
	// were built from.
	descriptor := BodyDescriptor{
		HeaderLen: int64(len(header)),
		BaseNonce: baseNonce,
		ChunkSize: cfg.chunkSize,
		AAD:       aad,
	}.clone()
	return &encryptReader{header: header, body: body}, descriptor, nil
}

// lengthCheckedReader enforces [WithContentLength]: it passes plaintext
// through and turns the source's EOF into [ErrContentLengthMismatch] when the
// byte count differs from the declared length (and fails as soon as the
// count exceeds it). The body cipher sees a read error, not EOF, so it never
// seals the final chunk: the ciphertext produced so far is truncated and
// fails to decrypt (aesstream.ErrTruncated) rather than passing as a
// valid-but-mislabeled object.
type lengthCheckedReader struct {
	r        io.Reader
	declared int64
	n        int64
}

func (l *lengthCheckedReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += int64(n)
	if l.n > l.declared {
		return n, fmt.Errorf("%w: declared %d, got more", ErrContentLengthMismatch, l.declared)
	}
	if err == io.EOF && l.n != l.declared {
		return n, fmt.Errorf("%w: declared %d, got %d", ErrContentLengthMismatch, l.declared, l.n)
	}
	return n, err
}

// encryptReader is the wire blob [Encrypt] hands back: the encoded envelope
// header, served from memory, followed by the ciphertext the body cipher
// produces as the plaintext is pulled through it.
//
// It implements io.WriterTo so an io.Copy from it writes the header and then
// each sealed chunk whole, rather than in io.Copy's 32 KiB pieces. Close
// releases the body cipher; reads after Close fail.
type encryptReader struct {
	header []byte // the envelope bytes not yet returned
	body   *aesstream.EncryptReader
}

func (e *encryptReader) Read(p []byte) (int, error) {
	if len(e.header) > 0 {
		n := copy(p, e.header)
		e.header = e.header[n:]
		return n, nil
	}
	return e.body.Read(p)
}

func (e *encryptReader) WriteTo(w io.Writer) (int64, error) {
	var total int64
	if len(e.header) > 0 {
		n, err := w.Write(e.header)
		e.header = e.header[n:]
		total += int64(n)
		if err != nil {
			return total, err
		}
		if len(e.header) > 0 {
			return total, io.ErrShortWrite
		}
	}
	n, err := e.body.WriteTo(w)
	return total + n, err
}

func (e *encryptReader) Close() error { return e.body.Close() }

// Decrypt recovers the plaintext from a FEE COSE_Encrypt (tag 96) envelope read
// from src.
//
// It decodes the envelope header from src (requiring the FEE typ), finds the
// recipient whose kid matches unwrap's key id, recovers the CEK through unwrap,
// and returns a streaming reader over the decrypted plaintext. Only the header
// is read up front; the detached ciphertext is streamed from src on demand.
//
// Decryption is streaming: a non-EOF error from the returned reader (see
// fee/aesstream) means the plaintext is incomplete and must be discarded. The
// reader is an [*aesstream.Reader]; a caller that closes it once done lets its
// chunk buffers be reused by the next stream.
//
// If the envelope carries no recipients (a COSE_Encrypt0), Decrypt returns
// [ErrNoRecipientsInEnvelope] — use [DecryptWithCEK]. If no recipient kid matches
// unwrap, it returns [ErrNoMatchingRecipient] without attempting an unwrap. If
// the matched recipient's wrapped CEK cannot be recovered (e.g. the wrong key),
// the unwrap error is returned and no plaintext reader is produced.
func Decrypt(src io.Reader, unwrap RecipientUnwrapper) (io.Reader, error) {
	if src == nil {
		return nil, errors.New("fee: nil envelope reader")
	}
	if unwrap == nil {
		return nil, ErrNilUnwrapper
	}

	env, ciphertext, err := cose.DecodeReader(src, envelopeDecodeOptions...)
	if err != nil {
		return nil, fmt.Errorf("fee: decoding envelope: %w", err)
	}
	if len(env.Recipients) == 0 {
		return nil, ErrNoRecipientsInEnvelope
	}

	match, err := matchRecipient(env.Recipients, unwrap.keyID())
	if err != nil {
		return nil, err
	}
	cek, err := unwrap.unwrap(match)
	if err != nil {
		return nil, err
	}
	// The recovered CEK is ours; wipe it once openStream has copied it into the
	// body cipher (synchronously, before it returns).
	defer zero(cek)

	return openStream(env, ciphertext, cek)
}

// DecryptWithCEK is [Decrypt] with a caller-provided content-encryption key
// instead of one recovered from an in-envelope recipient — for when the CEK was
// obtained out of band (e.g. unwrapped by a custody service). It accepts either
// a COSE_Encrypt (tag 96) or a recipient-less COSE_Encrypt0 (tag 16); any
// recipients are ignored. cek must be 32 bytes (AES-256).
//
// The caller retains ownership of cek: it is copied into the body cipher but
// neither retained nor wiped by this call.
func DecryptWithCEK(src io.Reader, cek []byte) (io.Reader, error) {
	if src == nil {
		return nil, errors.New("fee: nil envelope reader")
	}
	if err := checkCEK(cek); err != nil {
		return nil, err
	}
	env, ciphertext, err := cose.DecodeReader(src, envelopeDecodeOptions...)
	if err != nil {
		return nil, fmt.Errorf("fee: decoding envelope: %w", err)
	}
	return openStream(env, ciphertext, cek)
}

// openStream is the shared core of Decrypt and DecryptWithCEK: given a decoded
// envelope, its detached ciphertext stream, and the content-encryption key, it
// validates the body parameters and returns the streaming plaintext reader.
//
// It does not retain cek past its own return: aesstream.NewReader internalizes
// the CEK (into a GCM AEAD) synchronously before openStream returns, so a caller
// may wipe cek as soon as it returns — even though the returned reader decrypts
// lazily on later reads, which work from the internalized key, never the cek
// slice.
func openStream(env *cose.Envelope, ciphertext io.Reader, cek []byte) (io.Reader, error) {
	body, aad, err := buildBodyParamsWithAAD(env)
	if err != nil {
		return nil, err
	}
	r, err := aesstream.NewReader(ciphertext, body.streamConfig(cek, aad))
	if err != nil {
		return nil, fmt.Errorf("fee: initializing body cipher: %w", err)
	}
	if body.plaintextLength >= 0 {
		return &declaredLengthReader{r: r, declared: body.plaintextLength}, nil
	}
	return r, nil
}

// declaredLengthReader holds a whole-object read to the envelope's declared
// plaintext length, so it accepts exactly the blobs the range path does: a
// stream that authenticates to its end but yields a different length fails
// with [ErrSizeMismatch] instead of a clean EOF.
type declaredLengthReader struct {
	r        io.Reader
	declared int64
	n        int64
}

func (d *declaredLengthReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	d.n += int64(n)
	if d.n > d.declared {
		return n, fmt.Errorf("%w: envelope declares %d plaintext bytes, the stream holds more", ErrSizeMismatch, d.declared)
	}
	if err == io.EOF && d.n != d.declared {
		return n, fmt.Errorf("%w: envelope declares %d plaintext bytes, the stream holds %d", ErrSizeMismatch, d.declared, d.n)
	}
	return n, err
}

// bodyParams is the validated STREAM configuration a FEE envelope's body header
// carries: everything fee/aesstream needs to size and locate the detached
// ciphertext apart from the content-encryption key and Enc_structure AAD.
//
// [buildBodyParamsWithAAD] rebuilds that AAD alongside the validated params, and
// [BodyDescriptor] caches the same inputs plus the envelope's encoded length —
// where the ciphertext starts within a stored blob. That is what a caller caches
// and what a range read needs; a whole-object read has neither the number (the
// streaming decoder does not report it) nor a use for it, so the shapes stay
// distinct and [BodyDescriptor.bodyParams] / [BodyDescriptor.aad] convert one
// way.
type bodyParams struct {
	baseNonce []byte
	chunkSize int
	// plaintextLength is the declared plaintext length, or -1 when the
	// envelope does not declare one.
	plaintextLength int64
}

// streamConfig returns the fee/aesstream configuration for decrypting a body
// with these parameters under cek, authenticating aad as the envelope
// Enc_structure. It is the only place FEE body parameters become a stream
// configuration, so the whole-object reader ([openStream]) and the range reader
// ([spanRangeReader]) cannot drift apart in how they configure the cipher.
func (b bodyParams) streamConfig(cek, aad []byte) aesstream.Config {
	return aesstream.Config{
		Key:       cek,
		BaseNonce: b.baseNonce,
		AAD:       aad,
		ChunkSize: b.chunkSize,
	}
}

// validateBodyParams checks a decoded envelope's FEE body headers — every FEE
// parameter is protected, the algorithm is the chunked AES-256-GCM-STREAM
// cipher, the base nonce (iv) is present, the chunk size is present and in
// range, and a declared plaintext length is a non-negative integer.
//
// It is shared by the whole-object path's AAD-building resolution
// ([buildBodyParamsWithAAD]) and the header-only sizing path ([PlaintextSize]),
// so both accept exactly the same envelopes and report the same errors for a
// body header they cannot honour.
func validateBodyParams(env *cose.Envelope) (bodyParams, error) {
	if err := checkCrit(env.Headers, bodyUnderstoodLabels); err != nil {
		return bodyParams{}, err
	}
	// The nonce is the iv, never rebuilt from a Partial IV, so a Partial IV in
	// either bucket would be a second, conflicting instruction for it.
	if env.Headers.Protected.Has(cose.HeaderLabelPartialIV) || env.Headers.Unprotected.Has(cose.HeaderLabelPartialIV) {
		return bodyParams{}, fmt.Errorf("%w: Partial IV is not supported", ErrMalformedEnvelope)
	}

	// Every FEE parameter belongs in the protected header, where the AAD
	// authenticates it. A copy in the unprotected header would be
	// unauthenticated and ambiguous, so it makes the envelope malformed.
	for _, label := range bodyContentLabels {
		if env.Headers.Unprotected.Has(label) {
			return bodyParams{}, fmt.Errorf("%w: header %d must be protected", ErrMalformedEnvelope, label)
		}
	}

	alg, ok := env.Headers.Protected.Int(cose.HeaderLabelAlg)
	if !ok {
		return bodyParams{}, fmt.Errorf("%w: body algorithm header missing or not an integer", ErrUnsupportedBodyAlg)
	}
	if alg != algChunkedAES256GCMStream {
		return bodyParams{}, fmt.Errorf("%w: body algorithm %d is not chunked AES-256-GCM-STREAM", ErrUnsupportedBodyAlg, alg)
	}

	baseNonce, ok := env.Headers.Protected.Bytes(cose.HeaderLabelIV)
	if !ok {
		return bodyParams{}, fmt.Errorf("%w: missing iv (base nonce)", ErrMalformedEnvelope)
	}

	chunkSize, ok := env.Headers.Protected.Int(labelChunkSize)
	if !ok {
		return bodyParams{}, fmt.Errorf("%w: chunk-size header missing or not an integer", ErrMalformedEnvelope)
	}
	if chunkSize < int64(aesstream.MinChunkSize) || chunkSize > int64(aesstream.MaxChunkSize) {
		return bodyParams{}, fmt.Errorf("%w: declared chunk size %d out of range [%d, %d]",
			ErrMalformedEnvelope, chunkSize, aesstream.MinChunkSize, aesstream.MaxChunkSize)
	}

	plaintextLength := int64(-1)
	if env.Headers.Protected.Has(labelPlaintextLength) {
		n, ok := env.Headers.Protected.Int(labelPlaintextLength)
		if !ok || n < 0 {
			return bodyParams{}, fmt.Errorf("%w: plaintext-length header is not a non-negative integer", ErrMalformedEnvelope)
		}
		plaintextLength = n
	}

	return bodyParams{baseNonce: baseNonce, chunkSize: int(chunkSize), plaintextLength: plaintextLength}, nil
}

// buildBodyParamsWithAAD validates the body headers and rebuilds the
// Enc_structure AAD that the encoder bound into every chunk.
func buildBodyParamsWithAAD(env *cose.Envelope) (bodyParams, []byte, error) {
	body, err := validateBodyParams(env)
	if err != nil {
		return bodyParams{}, nil, err
	}

	// The decrypt-side AAD is rebuilt from the decoded envelope, using the
	// Enc_structure context that matches its tag — byte-identical to the value
	// the encoder bound into every chunk.
	aad, err := env.EncStructure(nil)
	if err != nil {
		return bodyParams{}, nil, fmt.Errorf("fee: building envelope AAD: %w", err)
	}

	return body, aad, nil
}

// checkCEK reports whether a caller-provided content-encryption key is the right
// length for the FEE body cipher. It is the one spelling of the check every
// external-CEK entry point applies, so they all report ErrInvalidCEK the same way.
func checkCEK(cek []byte) error {
	if len(cek) != aesstream.KeySize {
		return fmt.Errorf("%w, got %d", ErrInvalidCEK, len(cek))
	}
	return nil
}

// matchRecipient returns the first recipient whose kid equals want. A recipient
// without a kid header never matches. An empty want, or no match, yields
// ErrNoMatchingRecipient.
func matchRecipient(recipients []*cose.Recipient, want []byte) (*cose.Recipient, error) {
	if len(want) == 0 {
		return nil, ErrNoMatchingRecipient
	}
	for _, r := range recipients {
		if kid, ok := r.Headers.Unprotected.Bytes(cose.HeaderLabelKID); ok && bytes.Equal(kid, want) {
			return r, nil
		}
	}
	return nil, ErrNoMatchingRecipient
}

// zero overwrites b, a best-effort wipe of the CEK once it has been copied into
// the body cipher (and, on encrypt, wrapped to every recipient). It wraps the
// built-in clear so callers can defer it (a bare defer clear(b) is not allowed);
// like the loop it replaced, it is best-effort — Go does not guarantee the write
// survives dead-store elimination.
func zero(b []byte) {
	clear(b)
}
