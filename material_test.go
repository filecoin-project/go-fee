package fee_test

import (
	"bytes"
	"io"
	"math"
	"testing"

	"github.com/filecoin-project/go-fee"
	"github.com/filecoin-project/go-fee/aeskw"
	"github.com/filecoin-project/go-fee/aesstream"
	"github.com/filecoin-project/go-fee/cose"
	"github.com/stretchr/testify/require"
)

// blobLocationRow is the shape a metadata store persists per encrypted blob,
// modelled on the consumer this API exists for: the four BodyMaterial columns,
// the key-management columns that let the row's CEK be recovered, and the blob's
// size and location.
//
// The read half of every test below reads *only* from a value of this type. That
// is the point of the exercise: if the range path needed anything a store could
// not persist, these tests would not compile.
type blobLocationRow struct {
	// Key management: the CEK wrapped under a store-held key, never the CEK.
	regionWrappedCEK   []byte
	regionKeyVersion   string
	tenantRecipientKID string

	// Body material. chunkSize is int64 rather than int because a SQL bigint is
	// what a store round-trips, so the conversion is part of what is tested.
	headerLen int64
	baseNonce []byte
	chunkSize int64
	aad       []byte

	// Location.
	size int64
}

// material rebuilds the BodyMaterial from the persisted columns, as a reader
// would after loading the row.
func (r blobLocationRow) material() fee.BodyMaterial {
	return fee.BodyMaterial{
		HeaderLen: r.headerLen,
		BaseNonce: r.baseNonce,
		ChunkSize: int(r.chunkSize),
		AAD:       r.aad,
	}
}

// encryptWithMaterial seals plaintext under cek and returns the wire blob
// together with the material captured from the encrypt call — the write half of
// the store flow.
func encryptWithMaterial(t *testing.T, plaintext, cek []byte, recipients []fee.Recipient, opts ...fee.EncryptOption) ([]byte, fee.BodyMaterial) {
	t.Helper()
	enc, err := fee.EncryptWithCEK(bytes.NewReader(plaintext), cek, recipients, opts...)
	require.NoError(t, err)
	// Captured before a single byte is read, which is what lets a writer record
	// the row while the upload is still streaming.
	mat := enc.Material()
	blob, err := io.ReadAll(enc)
	require.NoError(t, err)
	require.NoError(t, enc.Close())
	return blob, mat
}

// requireNoEnvelopeRead asserts that nothing below headerLen was fetched: the
// whole purpose of caching the material is that the envelope is never read again.
func requireNoEnvelopeRead(t *testing.T, r *recordingReaderAt, headerLen int64) {
	t.Helper()
	for _, rd := range r.reads {
		require.GreaterOrEqualf(t, rd.off, headerLen,
			"read at offset %d (%d bytes) fell inside the %d-byte envelope; the cached material was not used",
			rd.off, rd.n, headerLen)
	}
}

// TestIngotWriteReadFlow is the acceptance criterion for the whole feature: a
// writer encrypts an object and persists what a store column can hold, and a
// later reader serves arbitrary byte ranges from those columns alone — fetching
// ciphertext only, never the envelope.
func TestIngotWriteReadFlow(t *testing.T) {
	const size = 4*rangeChunk + 123 // a partial final chunk

	// --- write path -------------------------------------------------------
	tenantKey := newX25519Key(t)
	regionKEK := newKEK(t)
	plaintext := patternBytes(size)

	cek := newCEK(t)
	regionWrapped, err := aeskw.Wrap(regionKEK, cek)
	require.NoError(t, err)

	blob, mat := encryptWithMaterial(t, plaintext, cek,
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, tenantKey.PublicKey())},
		fee.WithChunkSize(rangeChunk), fee.WithContentLength(size))

	// The writer's copy of the CEK is done with; only the wrapped form persists.
	clear(cek)

	row := blobLocationRow{
		regionWrappedCEK:   regionWrapped,
		regionKeyVersion:   "region-key-v1",
		tenantRecipientKID: string(ecdhKID),
		headerLen:          mat.HeaderLen,
		baseNonce:          mat.BaseNonce,
		chunkSize:          int64(mat.ChunkSize),
		aad:                mat.AAD,
		size:               int64(len(blob)),
	}

	t.Run("material describes the stored bytes", func(t *testing.T) {
		// Cross-check against the envelope actually written, so an extraction bug
		// on the encrypt side cannot hide behind a self-consistent round trip.
		env, rest, err := cose.Decode(blob, cose.WithExpectedType(fee.EnvelopeType))
		require.NoError(t, err)
		iv, ok := env.Headers.Unprotected.Bytes(cose.HeaderLabelIV)
		require.True(t, ok)
		aad, err := env.EncStructure(nil)
		require.NoError(t, err)

		// One comparison over the whole value, so a field added to BodyMaterial
		// cannot go unchecked here.
		require.Equal(t, fee.BodyMaterial{
			HeaderLen: int64(len(blob) - len(rest)),
			BaseNonce: iv,
			ChunkSize: rangeChunk,
			AAD:       aad,
		}, mat)
	})

	t.Run("plaintext size from the row alone", func(t *testing.T) {
		got, err := row.material().PlaintextSize(row.size)
		require.NoError(t, err)
		require.Equal(t, int64(size), got)
	})

	// --- read path --------------------------------------------------------
	for name, tc := range map[string]struct{ off, length int64 }{
		"whole object":         {0, size},
		"inside one chunk":     {100, 50},
		"aligned chunk":        {rangeChunk, rangeChunk},
		"crosses a boundary":   {rangeChunk - 10, 20},
		"partial final chunk":  {4 * rangeChunk, 123},
		"open-ended suffix":    {size - 50, math.MaxInt64},
		"single byte at start": {0, 1},
		"single byte at end":   {size - 1, 1},
		"empty range at eof":   {size, 0},
	} {
		t.Run(name, func(t *testing.T) {
			// Everything from here reads the row, never mat or the envelope.
			cek, err := aeskw.Unwrap(regionKEK, row.regionWrappedCEK)
			require.NoError(t, err)
			defer clear(cek)

			recording := newRecordingReaderAt(t, blob)
			r, err := fee.DecryptRangeWithMaterial(recording, row.size, row.material(),
				cek, tc.off, tc.length)
			require.NoError(t, err)

			want := plaintext[tc.off : tc.off+clampLen(size, tc.off, tc.length)]
			require.Equal(t, int64(len(want)), r.Len(), "Len must be known before reading")
			require.Equal(t, int64(size), r.Size())

			got, err := io.ReadAll(r)
			require.NoError(t, err)
			require.Equal(t, want, got)

			requireNoEnvelopeRead(t, recording, row.headerLen)
		})
	}
}

// TestEncryptedBlobMaterialIsACopy pins that Material hands back an independent
// value each call, so a caller that adjusts one — or a store that reuses the
// buffers it read a row into — cannot reach back into the blob's own state.
func TestEncryptedBlobMaterialIsACopy(t *testing.T) {
	enc, err := fee.EncryptWithCEK(bytes.NewReader(patternBytes(64)), newCEK(t), nil,
		fee.WithChunkSize(rangeChunk))
	require.NoError(t, err)
	defer enc.Close()

	first := enc.Material()
	first.AAD[0] ^= 0xff
	first.BaseNonce[0] ^= 0xff

	second := enc.Material()
	require.NotEqual(t, first.AAD, second.AAD)
	require.NotEqual(t, first.BaseNonce, second.BaseNonce)
}

// TestDecryptRangeWithMaterialEncrypt0 pins that material is envelope-form
// agnostic: a recipient-less COSE_Encrypt0 yields usable material with no flag
// and no special case, which is what lets BodyMaterial cache the finished AAD
// rather than a protected header plus a context discriminator.
func TestDecryptRangeWithMaterialEncrypt0(t *testing.T) {
	const size = 2 * rangeChunk
	plaintext := patternBytes(size)
	cek := newCEK(t)

	blob, mat := encryptWithMaterial(t, plaintext, cek, nil,
		fee.WithChunkSize(rangeChunk), fee.WithContentLength(size))

	// It really is the recipient-less form.
	tag, err := cose.PeekTag(blob)
	require.NoError(t, err)
	require.Equal(t, cose.TagCOSEEncrypt0, tag)

	recording := newRecordingReaderAt(t, blob)
	r, err := fee.DecryptRangeWithMaterial(recording, int64(len(blob)), mat, cek, 10, 4000)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, plaintext[10:4010], got)
	requireNoEnvelopeRead(t, recording, mat.HeaderLen)
}

// TestDecryptRangeWithMaterialMatchesEnvelopePath asserts the cached path and the
// envelope path are interchangeable — same bytes out for the same request, so
// caching is an optimisation and not a second behaviour to reason about.
func TestDecryptRangeWithMaterialMatchesEnvelopePath(t *testing.T) {
	const size = 3*rangeChunk + 7
	tenantKey := newX25519Key(t)
	plaintext := patternBytes(size)
	cek := newCEK(t)

	blob, mat := encryptWithMaterial(t, plaintext, cek,
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, tenantKey.PublicKey())},
		fee.WithChunkSize(rangeChunk), fee.WithContentLength(size))
	unwrapper := fee.NewECDHESUnwrapper(ecdhKID, tenantKey)

	for _, off := range []int64{0, 1, rangeChunk - 1, rangeChunk, 2 * rangeChunk, size - 7} {
		_, viaEnvelope := decryptRange(t, blob, unwrapper, off, 500)

		r, err := fee.DecryptRangeWithMaterial(bytes.NewReader(blob), int64(len(blob)), mat, cek, off, 500)
		require.NoError(t, err)
		viaMaterial, err := io.ReadAll(r)
		require.NoError(t, err)

		require.Equalf(t, viaEnvelope, viaMaterial, "paths disagree at off=%d", off)
	}
}

// TestBodyMaterialValidate covers the all-or-nothing rule a store mirrors before
// persisting a row: a partial record is refused rather than written and
// discovered unusable on some later read.
func TestBodyMaterialValidate(t *testing.T) {
	good := fee.BodyMaterial{
		HeaderLen: 128,
		BaseNonce: make([]byte, aesstream.BaseNonceSize),
		ChunkSize: rangeChunk,
		AAD:       []byte("enc-structure"),
	}
	require.NoError(t, good.Validate())

	for name, mutate := range map[string]func(*fee.BodyMaterial){
		"zero value":          func(m *fee.BodyMaterial) { *m = fee.BodyMaterial{} },
		"no header length":    func(m *fee.BodyMaterial) { m.HeaderLen = 0 },
		"negative header":     func(m *fee.BodyMaterial) { m.HeaderLen = -1 },
		"no base nonce":       func(m *fee.BodyMaterial) { m.BaseNonce = nil },
		"short base nonce":    func(m *fee.BodyMaterial) { m.BaseNonce = make([]byte, 3) },
		"no chunk size":       func(m *fee.BodyMaterial) { m.ChunkSize = 0 },
		"chunk size tiny":     func(m *fee.BodyMaterial) { m.ChunkSize = aesstream.MinChunkSize - 1 },
		"chunk size huge":     func(m *fee.BodyMaterial) { m.ChunkSize = aesstream.MaxChunkSize + 1 },
		"no aad":              func(m *fee.BodyMaterial) { m.AAD = nil },
		"empty (not nil) aad": func(m *fee.BodyMaterial) { m.AAD = []byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			m := good
			mutate(&m)
			require.ErrorIs(t, m.Validate(), fee.ErrIncompleteMaterial)

			// The range entry point rejects it up front for the same reason,
			// rather than letting it fail as an authentication error later.
			_, err := fee.DecryptRangeWithMaterial(bytes.NewReader([]byte("blob")), 4096, m,
				make([]byte, aesstream.KeySize), 0, 10)
			require.ErrorIs(t, err, fee.ErrIncompleteMaterial)
		})
	}
}

// TestDecryptRangeWithMaterialPoisoned is the safety property that makes caching
// this material acceptable: a row that has drifted from the bytes on disk fails
// loudly. Because BaseNonce and the AAD are bound into every chunk's GCM tag and
// HeaderLen decides which bytes are read at all, a wrong value can only produce
// an unreadable object — never plausible but incorrect plaintext.
func TestDecryptRangeWithMaterialPoisoned(t *testing.T) {
	const size = 3 * rangeChunk
	plaintext := patternBytes(size)
	cek := newCEK(t)
	blob, mat := encryptWithMaterial(t, plaintext, cek, nil,
		fee.WithChunkSize(rangeChunk), fee.WithContentLength(size))

	for name, mutate := range map[string]func(m *fee.BodyMaterial){
		"header length off by one": func(m *fee.BodyMaterial) { m.HeaderLen++ },
		"wrong base nonce": func(m *fee.BodyMaterial) {
			m.BaseNonce = bytes.Clone(m.BaseNonce)
			m.BaseNonce[0] ^= 0xff
		},
		"tampered aad": func(m *fee.BodyMaterial) {
			m.AAD = bytes.Clone(m.AAD)
			m.AAD[len(m.AAD)-1] ^= 0xff
		},
		"wrong chunk size": func(m *fee.BodyMaterial) { m.ChunkSize = rangeChunk * 2 },
	} {
		t.Run(name, func(t *testing.T) {
			poisoned := mat
			mutate(&poisoned)

			r, err := fee.DecryptRangeWithMaterial(bytes.NewReader(blob), int64(len(blob)),
				poisoned, cek, 0, 200)
			if err != nil {
				return // rejected at construction, which is a fine outcome
			}
			got, err := io.ReadAll(r)
			require.Error(t, err, "a poisoned row must not decrypt")
			require.NotEqual(t, plaintext[:200], got)
		})
	}
}

// TestDecryptRangeWithMaterialInvalidArgs covers the argument checks that do not
// depend on the material being right.
func TestDecryptRangeWithMaterialInvalidArgs(t *testing.T) {
	const size = 2 * rangeChunk
	plaintext := patternBytes(size)
	cek := newCEK(t)
	blob, mat := encryptWithMaterial(t, plaintext, cek, nil,
		fee.WithChunkSize(rangeChunk), fee.WithContentLength(size))
	blobSize := int64(len(blob))

	t.Run("short cek", func(t *testing.T) {
		_, err := fee.DecryptRangeWithMaterial(bytes.NewReader(blob), blobSize, mat,
			make([]byte, 16), 0, 10)
		require.ErrorIs(t, err, fee.ErrInvalidCEK)
	})

	t.Run("nil blob", func(t *testing.T) {
		_, err := fee.DecryptRangeWithMaterial(nil, blobSize, mat, cek, 0, 10)
		require.Error(t, err)
	})

	t.Run("blob shorter than its envelope", func(t *testing.T) {
		_, err := fee.DecryptRangeWithMaterial(bytes.NewReader(blob), mat.HeaderLen-1, mat, cek, 0, 10)
		require.ErrorIs(t, err, aesstream.ErrCiphertextSize)
	})

	t.Run("offset past the end", func(t *testing.T) {
		_, err := fee.DecryptRangeWithMaterial(bytes.NewReader(blob), blobSize, mat, cek, size+1, 10)
		require.ErrorIs(t, err, aesstream.ErrRange)
	})

	t.Run("negative offset", func(t *testing.T) {
		_, err := fee.DecryptRangeWithMaterial(bytes.NewReader(blob), blobSize, mat, cek, -1, 10)
		require.ErrorIs(t, err, aesstream.ErrRange)
	})
}
