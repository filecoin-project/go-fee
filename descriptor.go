package fee

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/filecoin-project/go-fee/aesstream"
)

// ErrIncompleteDescriptor means a [BodyDescriptor] is missing a field, or carries
// one that cannot describe a FEE body — a value that could not decrypt anything.
var ErrIncompleteDescriptor = errors.New("fee: incomplete body descriptor")

// BodyDescriptor is everything a range decrypt needs from a FEE envelope, so a
// caller that cached it can serve a byte range without fetching or decoding the
// envelope header at all. It is returned by [Encrypt] / [EncryptWithCEK] at
// encryption time and consumed by [DecryptRangeWithCEK] as its desc argument.
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
// The zero value is not usable; see [BodyDescriptor.Validate].
type BodyDescriptor struct {
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
	// BodyDescriptor identical for both envelope forms. The protected header
	// remains recoverable from it: it is the structure's second element.
	AAD []byte
}

// Validate reports whether m carries a complete, in-range description of a FEE
// body. It is the all-or-nothing check a store should apply before persisting
// material — a partially populated record would produce a row that no later
// range read could use.
//
// [DecryptRangeWithCEK] calls it when desc is non-nil, so a bad value fails
// there with [ErrIncompleteDescriptor] rather than as an authentication error
// further down.
func (m BodyDescriptor) Validate() error {
	if m.HeaderLen <= 0 {
		return fmt.Errorf("%w: header length %d is not positive", ErrIncompleteDescriptor, m.HeaderLen)
	}
	if len(m.BaseNonce) != aesstream.BaseNonceSize {
		return fmt.Errorf("%w: base nonce is %d bytes, want %d",
			ErrIncompleteDescriptor, len(m.BaseNonce), aesstream.BaseNonceSize)
	}
	if m.ChunkSize < aesstream.MinChunkSize || m.ChunkSize > aesstream.MaxChunkSize {
		return fmt.Errorf("%w: chunk size %d out of range [%d, %d]",
			ErrIncompleteDescriptor, m.ChunkSize, aesstream.MinChunkSize, aesstream.MaxChunkSize)
	}
	if len(m.AAD) == 0 {
		return fmt.Errorf("%w: missing AAD", ErrIncompleteDescriptor)
	}
	return nil
}

// PlaintextSize reports the total decrypted size of a blob of blobSize bytes
// described by m. It reads nothing and needs no key material, so it answers a
// HEAD request, fills in the total of a Content-Range header, or resolves a
// suffix range ("bytes=-N" is off = size-N) from cached metadata alone.
//
// blobSize is the whole stored object, envelope included, exactly as passed to
// [DecryptRangeWithCEK] when desc is non-nil. It reports [ErrIncompleteDescriptor]
// for an unusable m, and [aesstream.ErrCiphertextSize] if blobSize cannot
// describe a FEE blob at this header length and chunk size.
func (m BodyDescriptor) PlaintextSize(blobSize int64) (int64, error) {
	if err := m.Validate(); err != nil {
		return 0, err
	}
	return plaintextSizeFrom(blobSize, m.HeaderLen, m.ChunkSize)
}

// plaintextSizeFrom derives the total plaintext size of a blobSize-byte blob
// whose envelope occupies headerLen bytes and whose STREAM chunks carry chunkSize
// plaintext bytes each.
//
// It is shared by [BodyDescriptor.PlaintextSize] and the envelope-backed paths (via
// envelopePlaintextSize), so a blob size that cannot describe a FEE body is reported
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

// bodyParams returns the envelope body parameters m describes, for the range
// wiring it shares with the envelope-backed paths. HeaderLen is not among them:
// it says where the ciphertext starts, not how to decrypt it.
func (m BodyDescriptor) bodyParams() bodyParams {
	return bodyParams{baseNonce: m.BaseNonce, chunkSize: m.ChunkSize}
}

// aad returns the cached Enc_structure bytes m carries for body decryption.
func (m BodyDescriptor) aad() []byte {
	return m.AAD
}

// clone returns a deep copy, so a BodyDescriptor handed to a caller shares no
// backing array with the envelope it came from (and one handed back to us cannot
// be mutated underneath a live reader).
func (m BodyDescriptor) clone() BodyDescriptor {
	m.BaseNonce = bytes.Clone(m.BaseNonce)
	m.AAD = bytes.Clone(m.AAD)
	return m
}
