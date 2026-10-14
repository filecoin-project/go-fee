package fee

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/filecoin-project/go-fee/aesstream"
	"github.com/filecoin-project/go-fee/cose"
)

// ErrInvalidDescriptor means a [BodyDescriptor] is missing a field, or carries
// one that cannot describe a FEE body — a value that could not decrypt anything.
var ErrInvalidDescriptor = errors.New("fee: invalid body descriptor")

// BodyDescriptor is everything a range decrypt needs from a FEE envelope, so a
// caller that cached it can serve a byte range without fetching or decoding the
// envelope header at all. It is returned by [Encrypt] / [EncryptWithCEK] at
// encryption time and consumed by [DecryptRangeWithCEK] as its desc argument.
//
// It exists for stores that keep their own metadata alongside the blob: the
// envelope is a fixed prefix of every stored object, so re-reading it on each
// range request costs a round trip to the object store for bytes that never
// change. Persisting its two values next to the blob's location removes that
// round trip; the only per-request I/O left is the ciphertext the range overlaps.
//
// Both fields are non-secret — they are already in the clear at the front of
// the stored blob — so caching them discloses nothing that fetching the blob's
// first bytes would not. The content-encryption key is deliberately not part of
// it; how the CEK is stored and recovered is the caller's concern.
//
// AAD is the envelope's protected header wrapped in its Enc_structure, so the
// body parameters (base nonce, chunk size and any declared plaintext length)
// are read from it rather than cached beside it, and get the same checks as on
// the envelope-backed paths. In particular a declared plaintext length is
// checked against the blob size ([ErrSizeMismatch]).
//
// A cached copy cannot silently serve wrong data. AAD is bound into every
// chunk's AES-GCM tag, and HeaderLen determines which bytes are read, so a
// stale or corrupted value surfaces as an authentication failure
// ([aesstream.ErrCorrupted]) rather than as plausible-looking plaintext. The
// worst case is an unreadable object, not an incorrect one.
//
// The zero value is not usable; see [BodyDescriptor.Validate].
type BodyDescriptor struct {
	// HeaderLen is the encoded length of the envelope, and so the offset within
	// the blob at which the detached ciphertext begins.
	HeaderLen int64

	// AAD is the envelope's Enc_structure — the additional authenticated data
	// bound into every chunk. It is cached whole rather than rebuilt from the
	// protected header because the Enc_structure's context string differs
	// between a COSE_Encrypt and a recipient-less COSE_Encrypt0, a distinction
	// this value has no other way to record. Caching the finished bytes keeps
	// BodyDescriptor identical for both envelope forms. The protected header
	// is the structure's second element, and the body parameters are read
	// from it.
	AAD []byte
}

// Validate reports whether m carries a complete, in-range description of a FEE
// body. It is the all-or-nothing check a store should apply before persisting
// material — a partially populated record would produce a row that no later
// range read could use. AAD must be a well-formed Enc_structure whose
// protected header holds valid FEE body parameters.
//
// [DecryptRangeWithCEK] calls it when desc is non-nil, so a bad value fails
// there with [ErrInvalidDescriptor] rather than as an authentication error
// further down.
func (m BodyDescriptor) Validate() error {
	_, err := m.params()
	return err
}

// params validates m and returns the body parameters it describes, including
// the plaintext length its protected header declares, if any.
func (m BodyDescriptor) params() (bodyParams, error) {
	if m.HeaderLen <= 0 {
		return bodyParams{}, fmt.Errorf("%w: header length %d is not positive", ErrInvalidDescriptor, m.HeaderLen)
	}
	if len(m.AAD) == 0 {
		return bodyParams{}, fmt.Errorf("%w: missing AAD", ErrInvalidDescriptor)
	}

	// The AAD carries the protected header the encoder bound into every chunk,
	// and is held to the rules of an envelope's body header.
	_, protected, externalAAD, err := cose.ParseEncStructure(m.AAD)
	if err != nil {
		return bodyParams{}, fmt.Errorf("%w: AAD: %w", ErrInvalidDescriptor, err)
	}
	if len(externalAAD) != 0 {
		return bodyParams{}, fmt.Errorf("%w: AAD has external AAD, which FEE does not use", ErrInvalidDescriptor)
	}
	if typ, _ := protected.Text(cose.HeaderLabelType); typ != EnvelopeType {
		return bodyParams{}, fmt.Errorf("%w: AAD envelope type is %q, want %q", ErrInvalidDescriptor, typ, EnvelopeType)
	}
	body, err := validateBodyParams(&cose.Envelope{Headers: cose.Headers{Protected: protected, Unprotected: cose.Header{}}})
	if err != nil {
		return bodyParams{}, fmt.Errorf("%w: AAD: %w", ErrInvalidDescriptor, err)
	}
	return body, nil
}

// ChunkSize reports the STREAM plaintext chunk size, in bytes, that the
// protected header in m.AAD declares. It reports [ErrInvalidDescriptor] for an
// unusable m.
func (m BodyDescriptor) ChunkSize() (int, error) {
	body, err := m.params()
	if err != nil {
		return 0, err
	}
	return body.chunkSize, nil
}

// BaseNonce reports the STREAM base nonce, the envelope's iv, that the
// protected header in m.AAD declares. It is [aesstream.BaseNonceSize] bytes
// and is a fresh slice the caller owns. It reports [ErrInvalidDescriptor] for
// an unusable m.
func (m BodyDescriptor) BaseNonce() ([]byte, error) {
	body, err := m.params()
	if err != nil {
		return nil, err
	}
	return bytes.Clone(body.baseNonce), nil
}

// PlaintextSize reports the total decrypted size of a blob of blobSize bytes
// described by m. It reads nothing and needs no key material, so it answers a
// HEAD request, fills in the total of a Content-Range header, or resolves a
// suffix range ("bytes=-N" is start = size-N) from cached metadata alone.
//
// blobSize is the whole stored object, envelope included, exactly as passed to
// [DecryptRangeWithCEK] when desc is non-nil. It reports [ErrInvalidDescriptor]
// for an unusable m, [aesstream.ErrCiphertextSize] if blobSize cannot
// describe a FEE blob at this header length and chunk size, and
// [ErrSizeMismatch] if the protected header in AAD declares a plaintext length
// that blobSize contradicts.
func (m BodyDescriptor) PlaintextSize(blobSize int64) (int64, error) {
	body, err := m.params()
	if err != nil {
		return 0, err
	}
	return checkedPlaintextSize(blobSize, m.HeaderLen, body)
}

// plaintextSizeFrom derives the total plaintext size of a blobSize-byte blob
// whose envelope occupies headerLen bytes and whose STREAM chunks carry chunkSize
// plaintext bytes each.
//
// It underlies [checkedPlaintextSize], so a blob size that cannot describe a FEE
// body is reported the same way whether the parameters came from a cache or
// from the envelope.
func plaintextSizeFrom(blobSize, headerLen int64, chunkSize int) (int64, error) {
	ciphertextSize := blobSize - headerLen
	if ciphertextSize < 0 {
		return 0, fmt.Errorf("fee: blob size %d is shorter than its %d-byte envelope: %w",
			blobSize, headerLen, aesstream.ErrCiphertextSize)
	}
	n, err := aesstream.DecryptedSize(ciphertextSize, chunkSize)
	if err != nil {
		return 0, fmt.Errorf("fee: blob of %d ciphertext bytes: %w", ciphertextSize, err)
	}
	return n, nil
}

// clone returns a deep copy, so a BodyDescriptor handed to a caller shares no
// backing array with the envelope it came from (and one handed back to us cannot
// be mutated underneath a live reader).
func (m BodyDescriptor) clone() BodyDescriptor {
	m.AAD = bytes.Clone(m.AAD)
	return m
}
