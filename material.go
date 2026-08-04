package fee

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/filecoin-project/go-fee/aesstream"
)

// ErrIncompleteMaterial means a [BodyMaterial] is missing a field, or carries one
// that cannot describe a FEE body — a value that could not decrypt anything.
var ErrIncompleteMaterial = errors.New("fee: incomplete body material")

// BodyMaterial is everything a range decrypt needs from a FEE envelope, so a
// caller that cached it can serve a byte range without fetching or decoding the
// envelope header at all. It is obtained from [EncryptedBlob.Material] at
// encryption time and consumed by [DecryptRangeWithMaterial].
//
// It exists for stores that keep their own metadata alongside the blob: the
// envelope is a fixed prefix of every stored object, so re-reading it on each
// range request costs a round trip to the object store for bytes that never
// change. Persisting these four values next to the blob's location removes that
// round trip; the only per-request I/O left is the ciphertext the range overlaps.
//
// Every field is non-secret — all four are already in the clear at the front of
// the stored blob — so caching them discloses nothing that fetching the blob's
// first bytes would not. The content-encryption key is deliberately not part of
// it; how the CEK is stored and recovered is the caller's concern.
//
// A cached copy cannot silently serve wrong data. BaseNonce and AAD are bound
// into every chunk's AES-GCM tag, and HeaderLen and ChunkSize determine which
// bytes are read and under which nonce, so a stale or corrupted value surfaces
// as an authentication failure ([aesstream.ErrCorrupted]) rather than as
// plausible-looking plaintext. The worst case is an unreadable object, not an
// incorrect one.
//
// The zero value is not usable; see [BodyMaterial.Validate].
type BodyMaterial struct {
	// HeaderLen is the encoded length of the envelope, and so the offset within
	// the blob at which the detached ciphertext begins.
	HeaderLen int64

	// BaseNonce is the envelope's iv header: the STREAM base nonce every chunk
	// nonce is derived from. It is [aesstream.BaseNonceSize] bytes.
	BaseNonce []byte

	// ChunkSize is the STREAM plaintext chunk size, in bytes.
	ChunkSize int

	// AAD is the envelope's Enc_structure — the additional authenticated data
	// bound into every chunk. It is cached whole rather than rebuilt from the
	// protected header because the Enc_structure's context string differs
	// between a COSE_Encrypt and a recipient-less COSE_Encrypt0, a distinction
	// this value has no other way to record. Caching the finished bytes keeps
	// BodyMaterial identical for both envelope forms. The protected header
	// remains recoverable from it: it is the structure's second element.
	AAD []byte
}

// Validate reports whether m carries a complete, in-range description of a FEE
// body. It is the all-or-nothing check a store should apply before persisting
// material — a partially populated record would produce a row that no later
// range read could use.
//
// [DecryptRangeWithMaterial] calls it, so a bad value fails there with
// [ErrIncompleteMaterial] rather than as an authentication error further down.
func (m BodyMaterial) Validate() error {
	if m.HeaderLen <= 0 {
		return fmt.Errorf("%w: header length %d is not positive", ErrIncompleteMaterial, m.HeaderLen)
	}
	if len(m.BaseNonce) != aesstream.BaseNonceSize {
		return fmt.Errorf("%w: base nonce is %d bytes, want %d",
			ErrIncompleteMaterial, len(m.BaseNonce), aesstream.BaseNonceSize)
	}
	if m.ChunkSize < aesstream.MinChunkSize || m.ChunkSize > aesstream.MaxChunkSize {
		return fmt.Errorf("%w: chunk size %d out of range [%d, %d]",
			ErrIncompleteMaterial, m.ChunkSize, aesstream.MinChunkSize, aesstream.MaxChunkSize)
	}
	if len(m.AAD) == 0 {
		return fmt.Errorf("%w: missing AAD", ErrIncompleteMaterial)
	}
	return nil
}

// PlaintextSize reports the total decrypted size of a blob of blobSize bytes
// described by m. It reads nothing and needs no key material, so it answers a
// HEAD request, fills in the total of a Content-Range header, or resolves a
// suffix range ("bytes=-N" is off = size-N) from cached metadata alone.
//
// blobSize is the whole stored object, envelope included, exactly as passed to
// [DecryptRangeWithMaterial]. It reports [ErrIncompleteMaterial] for an unusable
// m, and [aesstream.ErrCiphertextSize] if blobSize cannot describe a FEE blob at
// this header length and chunk size.
func (m BodyMaterial) PlaintextSize(blobSize int64) (int64, error) {
	if err := m.Validate(); err != nil {
		return 0, err
	}
	return plaintextSizeFrom(blobSize, m.HeaderLen, m.ChunkSize)
}

// plaintextSizeFrom derives the total plaintext size of a blobSize-byte blob
// whose envelope occupies headerLen bytes and whose STREAM chunks carry chunkSize
// plaintext bytes each.
//
// It is shared by [BodyMaterial.PlaintextSize] and the envelope-backed paths (via
// plaintextSizeFor), so a blob size that cannot describe a FEE body is reported
// the same way whether the parameters came from a cache or from the envelope.
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

// body returns the envelope body parameters m describes, for the range wiring it
// shares with the envelope-backed paths. HeaderLen is not among them: it says
// where the ciphertext starts, not how to decrypt it.
func (m BodyMaterial) body() bodyParams {
	return bodyParams{baseNonce: m.BaseNonce, chunkSize: m.ChunkSize, aad: m.AAD}
}

// clone returns a deep copy, so a BodyMaterial handed to a caller shares no
// backing array with the envelope it came from (and one handed back to us cannot
// be mutated underneath a live reader).
func (m BodyMaterial) clone() BodyMaterial {
	m.BaseNonce = bytes.Clone(m.BaseNonce)
	m.AAD = bytes.Clone(m.AAD)
	return m
}
