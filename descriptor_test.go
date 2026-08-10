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
// modelled on the consumer this API exists for: the four BodyDescriptor columns,
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

	// Body descriptor. chunkSize is int64 rather than int because a SQL bigint is
	// what a store round-trips, so the conversion is part of what is tested.
	headerLen int64
	baseNonce []byte
	chunkSize int64
	aad       []byte

	// Location.
	size int64
}

// descriptor rebuilds the BodyDescriptor from the persisted columns, as a reader
// would after loading the row.
func (r blobLocationRow) descriptor() fee.BodyDescriptor {
	return fee.BodyDescriptor{
		HeaderLen: r.headerLen,
		BaseNonce: r.baseNonce,
		ChunkSize: int(r.chunkSize),
		AAD:       r.aad,
	}
}

// encryptWithDescriptor seals plaintext under cek and returns the wire blob
// together with the descriptor captured from the encrypt call — the write half of
// the store flow.
func encryptWithDescriptor(t *testing.T, plaintext, cek []byte, recipients []fee.Recipient, opts ...fee.EncryptOption) ([]byte, fee.BodyDescriptor) {
	t.Helper()
	// The descriptor arrives before a single byte is read, which is what lets a
	// writer record the row while the upload is still streaming.
	enc, desc, err := fee.EncryptWithCEK(bytes.NewReader(plaintext), cek, recipients, opts...)
	require.NoError(t, err)
	blob, err := io.ReadAll(enc)
	require.NoError(t, err)
	require.NoError(t, enc.Close())
	return blob, desc
}

// requireNoEnvelopeRead asserts that nothing below headerLen was fetched: the
// whole purpose of caching the descriptor is that the envelope is never read again.
func requireNoEnvelopeRead(t *testing.T, r *recordingReaderAt, headerLen int64) {
	t.Helper()
	for _, rd := range r.reads {
		require.GreaterOrEqualf(t, rd.off, headerLen,
			"read at offset %d (%d bytes) fell inside the %d-byte envelope; the cached descriptor was not used",
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

	blob, desc := encryptWithDescriptor(t, plaintext, cek,
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, tenantKey.PublicKey())},
		fee.WithChunkSize(rangeChunk), fee.WithContentLength(size))

	// The writer's copy of the CEK is done with; only the wrapped form persists.
	clear(cek)

	row := blobLocationRow{
		regionWrappedCEK:   regionWrapped,
		regionKeyVersion:   "region-key-v1",
		tenantRecipientKID: string(ecdhKID),
		headerLen:          desc.HeaderLen,
		baseNonce:          desc.BaseNonce,
		chunkSize:          int64(desc.ChunkSize),
		aad:                desc.AAD,
		size:               int64(len(blob)),
	}

	t.Run("descriptor describes the stored bytes", func(t *testing.T) {
		// Cross-check against the envelope actually written, so an extraction bug
		// on the encrypt side cannot hide behind a self-consistent round trip.
		env, rest, err := cose.Decode(blob, cose.WithExpectedType(fee.EnvelopeType))
		require.NoError(t, err)
		iv, ok := env.Headers.Unprotected.Bytes(cose.HeaderLabelIV)
		require.True(t, ok)
		aad, err := env.EncStructure(nil)
		require.NoError(t, err)

		// One comparison over the whole value, so a field added to BodyDescriptor
		// cannot go unchecked here.
		require.Equal(t, fee.BodyDescriptor{
			HeaderLen: int64(len(blob) - len(rest)),
			BaseNonce: iv,
			ChunkSize: rangeChunk,
			AAD:       aad,
		}, desc)
	})

	t.Run("plaintext size from the row alone", func(t *testing.T) {
		got, err := row.descriptor().PlaintextSize(row.size)
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
			// Everything from here reads the row, never desc or the envelope.
			cek, err := aeskw.Unwrap(regionKEK, row.regionWrappedCEK)
			require.NoError(t, err)
			defer clear(cek)

			recording := newRecordingReaderAt(t, blob)
			desc := row.descriptor()
			r, err := fee.DecryptRangeWithCEK(recording, row.size, cek, tc.off, tc.length, &desc)
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

// TestEncryptDescriptorDoesNotAliasTheStream pins that the descriptor handed back
// shares no backing array with the encryption still in flight: a caller that
// adjusts its copy — or a store that reuses the buffers it read a row into —
// cannot disturb the blob being produced.
func TestEncryptDescriptorDoesNotAliasTheStream(t *testing.T) {
	cek := newCEK(t)
	plaintext := patternBytes(2 * rangeChunk)

	rc, desc, err := fee.EncryptWithCEK(bytes.NewReader(plaintext), cek, nil,
		fee.WithChunkSize(rangeChunk))
	require.NoError(t, err)
	defer rc.Close()

	// Scribble on the caller's copy before a single byte is read, keeping the
	// values a store would have persisted.
	kept := fee.BodyDescriptor{
		HeaderLen: desc.HeaderLen,
		BaseNonce: bytes.Clone(desc.BaseNonce),
		ChunkSize: desc.ChunkSize,
		AAD:       bytes.Clone(desc.AAD),
	}
	desc.BaseNonce[0] ^= 0xff
	desc.AAD[0] ^= 0xff

	blob, err := io.ReadAll(rc)
	require.NoError(t, err)

	// The blob still decrypts under the pristine values, so the mutation never
	// reached the cipher or the encoded header.
	r, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), int64(len(blob)), cek, 0, int64(len(plaintext)), &kept)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// TestDecryptRangeWithCEKAndBodyDescriptorEncrypt0 pins that the descriptor is
// envelope-form agnostic: a recipient-less COSE_Encrypt0 yields a usable
// descriptor with no flag and no special case, which is what lets
// BodyDescriptor cache the finished AAD rather than a protected header plus a
// context discriminator.
func TestDecryptRangeWithCEKAndBodyDescriptorEncrypt0(t *testing.T) {
	const size = 2 * rangeChunk
	plaintext := patternBytes(size)
	cek := newCEK(t)

	blob, desc := encryptWithDescriptor(t, plaintext, cek, nil,
		fee.WithChunkSize(rangeChunk), fee.WithContentLength(size))

	// It really is the recipient-less form.
	tag, err := cose.PeekTag(blob)
	require.NoError(t, err)
	require.Equal(t, cose.TagCOSEEncrypt0, tag)

	recording := newRecordingReaderAt(t, blob)
	r, err := fee.DecryptRangeWithCEK(recording, int64(len(blob)), cek, 10, 4000, &desc)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, plaintext[10:4010], got)
	requireNoEnvelopeRead(t, recording, desc.HeaderLen)
}

// TestDecryptRangeWithCEKAndBodyDescriptorMatchesEnvelopePath asserts the cached
// path and the envelope path are interchangeable — same bytes out for the same
// request, so caching is an optimisation and not a second behaviour to reason
// about.
func TestDecryptRangeWithCEKAndBodyDescriptorMatchesEnvelopePath(t *testing.T) {
	const size = 3*rangeChunk + 7
	tenantKey := newX25519Key(t)
	plaintext := patternBytes(size)
	cek := newCEK(t)

	blob, desc := encryptWithDescriptor(t, plaintext, cek,
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, tenantKey.PublicKey())},
		fee.WithChunkSize(rangeChunk), fee.WithContentLength(size))
	unwrapper := fee.NewECDHESUnwrapper(ecdhKID, tenantKey)

	for _, off := range []int64{0, 1, rangeChunk - 1, rangeChunk, 2 * rangeChunk, size - 7} {
		_, viaEnvelope := decryptRange(t, blob, unwrapper, off, 500)

		r, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), int64(len(blob)), cek, off, 500, &desc)
		require.NoError(t, err)
		viaDescriptor, err := io.ReadAll(r)
		require.NoError(t, err)

		require.Equalf(t, viaEnvelope, viaDescriptor, "paths disagree at off=%d", off)
	}
}

// TestBodyDescriptorValidate covers the all-or-nothing rule a store mirrors before
// persisting a row: a partial record is refused rather than written and
// discovered unusable on some later read.
func TestBodyDescriptorValidate(t *testing.T) {
	good := fee.BodyDescriptor{
		HeaderLen: 128,
		BaseNonce: make([]byte, aesstream.BaseNonceSize),
		ChunkSize: rangeChunk,
		AAD:       []byte("enc-structure"),
	}
	require.NoError(t, good.Validate())

	for name, mutate := range map[string]func(*fee.BodyDescriptor){
		"zero value":          func(m *fee.BodyDescriptor) { *m = fee.BodyDescriptor{} },
		"no header length":    func(m *fee.BodyDescriptor) { m.HeaderLen = 0 },
		"negative header":     func(m *fee.BodyDescriptor) { m.HeaderLen = -1 },
		"no base nonce":       func(m *fee.BodyDescriptor) { m.BaseNonce = nil },
		"short base nonce":    func(m *fee.BodyDescriptor) { m.BaseNonce = make([]byte, 3) },
		"no chunk size":       func(m *fee.BodyDescriptor) { m.ChunkSize = 0 },
		"chunk size tiny":     func(m *fee.BodyDescriptor) { m.ChunkSize = aesstream.MinChunkSize - 1 },
		"chunk size huge":     func(m *fee.BodyDescriptor) { m.ChunkSize = aesstream.MaxChunkSize + 1 },
		"no aad":              func(m *fee.BodyDescriptor) { m.AAD = nil },
		"empty (not nil) aad": func(m *fee.BodyDescriptor) { m.AAD = []byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			m := good
			mutate(&m)
			require.ErrorIs(t, m.Validate(), fee.ErrIncompleteDescriptor)

			// The range entry point rejects it up front for the same reason,
			// rather than letting it fail as an authentication error later.
			_, err := fee.DecryptRangeWithCEK(bytes.NewReader([]byte("blob")), 4096,
				make([]byte, aesstream.KeySize), 0, 10, &m)
			require.ErrorIs(t, err, fee.ErrIncompleteDescriptor)
		})
	}
}

// TestDecryptRangeWithCEKAndBodyDescriptorPoisoned is the safety property that
// makes caching this descriptor acceptable: a row that has drifted from the
// bytes on disk fails loudly. Because BaseNonce and the AAD are bound into every
// chunk's GCM tag and HeaderLen decides which bytes are read at all, a wrong
// value can only produce an unreadable object — never plausible but incorrect
// plaintext.
func TestDecryptRangeWithCEKAndBodyDescriptorPoisoned(t *testing.T) {
	const size = 3 * rangeChunk
	plaintext := patternBytes(size)
	cek := newCEK(t)
	blob, desc := encryptWithDescriptor(t, plaintext, cek, nil,
		fee.WithChunkSize(rangeChunk), fee.WithContentLength(size))

	for name, mutate := range map[string]func(m *fee.BodyDescriptor){
		"header length off by one": func(m *fee.BodyDescriptor) { m.HeaderLen++ },
		"wrong base nonce": func(m *fee.BodyDescriptor) {
			m.BaseNonce = bytes.Clone(m.BaseNonce)
			m.BaseNonce[0] ^= 0xff
		},
		"tampered aad": func(m *fee.BodyDescriptor) {
			m.AAD = bytes.Clone(m.AAD)
			m.AAD[len(m.AAD)-1] ^= 0xff
		},
		"wrong chunk size": func(m *fee.BodyDescriptor) { m.ChunkSize = rangeChunk * 2 },
	} {
		t.Run(name, func(t *testing.T) {
			poisoned := desc
			mutate(&poisoned)

			r, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), int64(len(blob)), cek, 0, 200, &poisoned)
			if err != nil {
				return // rejected at construction, which is a fine outcome
			}
			got, err := io.ReadAll(r)
			require.Error(t, err, "a poisoned row must not decrypt")
			require.NotEqual(t, plaintext[:200], got)
		})
	}
}

// TestDecryptRangeWithCEKAndBodyDescriptorInvalidArgs covers the argument checks
// that do not depend on the descriptor being right.
func TestDecryptRangeWithCEKAndBodyDescriptorInvalidArgs(t *testing.T) {
	const size = 2 * rangeChunk
	plaintext := patternBytes(size)
	cek := newCEK(t)
	blob, desc := encryptWithDescriptor(t, plaintext, cek, nil,
		fee.WithChunkSize(rangeChunk), fee.WithContentLength(size))
	blobSize := int64(len(blob))

	t.Run("short cek", func(t *testing.T) {
		_, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), blobSize, make([]byte, 16), 0, 10, &desc)
		require.ErrorIs(t, err, fee.ErrInvalidCEK)
	})

	t.Run("nil blob", func(t *testing.T) {
		_, err := fee.DecryptRangeWithCEK(nil, blobSize, cek, 0, 10, &desc)
		require.Error(t, err)
	})

	t.Run("blob shorter than its envelope", func(t *testing.T) {
		_, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), desc.HeaderLen-1, cek, 0, 10, &desc)
		require.ErrorIs(t, err, aesstream.ErrCiphertextSize)
	})

	t.Run("offset past the end", func(t *testing.T) {
		_, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), blobSize, cek, size+1, 10, &desc)
		require.ErrorIs(t, err, aesstream.ErrRange)
	})

	t.Run("negative offset", func(t *testing.T) {
		_, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), blobSize, cek, -1, 10, &desc)
		require.ErrorIs(t, err, aesstream.ErrRange)
	})
}
