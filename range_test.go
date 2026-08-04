package fee_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"slices"
	"testing"

	"github.com/filecoin-project/go-fee"
	"github.com/filecoin-project/go-fee/aesstream"
	"github.com/filecoin-project/go-fee/cose"
	"github.com/stretchr/testify/require"
)

// rangeChunk is the chunk size the range tests encrypt at: the smallest the FEE
// spec allows, so a multi-chunk object stays cheap to build and every chunk
// boundary is easy to target.
const rangeChunk = aesstream.MinChunkSize

// recordingReaderAt is an io.ReaderAt over a fixed blob that records every
// interval it is asked for, so a test can prove which bytes a range decrypt
// actually touched.
type recordingReaderAt struct {
	blob   *bytes.Reader
	reads  []readInterval
	reject bool // fail instead of serving, to prove no read happens at all
	t      *testing.T
}

// readInterval is one ReadAt request: the offset and the number of bytes served.
type readInterval struct{ off, n int64 }

func newRecordingReaderAt(t *testing.T, blob []byte) *recordingReaderAt {
	t.Helper()
	return &recordingReaderAt{blob: bytes.NewReader(blob), t: t}
}

func (r *recordingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if r.reject {
		r.t.Errorf("unexpected ReadAt(off=%d, len=%d)", off, len(p))
		return 0, errors.New("recordingReaderAt: read not expected")
	}
	n, err := r.blob.ReadAt(p, off)
	r.reads = append(r.reads, readInterval{off: off, n: int64(n)})
	return n, err
}

// rangeFixture is an encrypted object plus everything needed to range-decrypt it.
type rangeFixture struct {
	plaintext []byte
	blob      []byte
	unwrapper fee.RecipientUnwrapper
}

// newRangeFixture encrypts n deterministic plaintext bytes to a single ECDH-ES
// recipient at rangeChunk, the common setup for the range tests.
func newRangeFixture(t *testing.T, n int, opts ...fee.EncryptOption) rangeFixture {
	t.Helper()
	priv := newX25519Key(t)
	plaintext := patternBytes(n)
	opts = append([]fee.EncryptOption{fee.WithChunkSize(rangeChunk)}, opts...)
	blob, err := encrypt(t, plaintext, []fee.Recipient{
		fee.NewECDHESRecipient(ecdhKID, priv.PublicKey()),
	}, opts...)
	require.NoError(t, err)
	return rangeFixture{
		plaintext: plaintext,
		blob:      blob,
		unwrapper: fee.NewECDHESUnwrapper(ecdhKID, priv),
	}
}

// encryptWithCEK runs fee.EncryptWithCEK over plaintext and reads the streamed
// envelope||ciphertext into a single blob, the external-CEK counterpart of the
// encrypt helper.
func encryptWithCEK(t *testing.T, plaintext, cek []byte, recipients []fee.Recipient, opts ...fee.EncryptOption) ([]byte, error) {
	t.Helper()
	r, _, err := fee.EncryptWithCEK(bytes.NewReader(plaintext), cek, recipients, opts...)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// hexBytes decodes a hex literal, for the handful of tests that pin behaviour
// against exact wire bytes rather than an encrypted fixture.
func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// clampLen is the plaintext length a range request of [off, off+length) actually
// yields from a size-byte object: length clamped to what is left from off. The
// subtraction comes first, so an open-ended math.MaxInt64 length cannot overflow.
func clampLen(size, off, length int64) int64 {
	return min(length, size-off)
}

// headerLenOf reports the encoded envelope length of a blob holding size
// plaintext bytes at rangeChunk, by subtracting the ciphertext the STREAM
// geometry accounts for.
func headerLenOf(blob []byte, size int64) int64 {
	return int64(len(blob)) - aesstream.EncryptedSize(size, rangeChunk)
}

// decryptRange range-decrypts [off, off+length) from blob and returns the reader
// alongside the bytes it emitted, asserting a clean stream.
func decryptRange(t *testing.T, blob []byte, u fee.RecipientUnwrapper, off, length int64) (*fee.RangeReader, []byte) {
	t.Helper()
	r, err := fee.DecryptRange(bytes.NewReader(blob), int64(len(blob)), u, off, length)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	return r, got
}

// TestDecryptRangeRoundTrip is the acceptance criterion that one call with an
// envelope, unwrap material and a byte range returns exactly the requested
// plaintext — across the interesting geometries of a multi-chunk object: whole
// object, within one chunk, spanning a boundary, exactly one aligned chunk, into
// the short final chunk, and single bytes at each end.
func TestDecryptRangeRoundTrip(t *testing.T) {
	const size = 3*rangeChunk + rangeChunk/2 // 3.5 chunks
	f := newRangeFixture(t, size)

	cases := []struct {
		name        string
		off, length int64
	}{
		{"whole object", 0, size},
		{"first byte", 0, 1},
		{"last byte", size - 1, 1},
		{"within first chunk", 100, 500},
		{"within middle chunk", rangeChunk + 7, 1000},
		{"across one boundary", rangeChunk - 10, 20},
		{"across two boundaries", rangeChunk - 10, 2*rangeChunk + 20},
		{"exactly one aligned chunk", rangeChunk, rangeChunk},
		{"aligned start, unaligned end", 2 * rangeChunk, rangeChunk + 5},
		{"whole short final chunk", 3 * rangeChunk, rangeChunk / 2},
		{"into final chunk", 3*rangeChunk - 5, 100},
		{"ends exactly on boundary", rangeChunk / 2, rangeChunk / 2},
		{"length past end clamps", size - 10, 1000},
		{"open-ended range clamps", rangeChunk, math.MaxInt64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, got := decryptRange(t, f.blob, f.unwrapper, tc.off, tc.length)

			wantLen := clampLen(size, tc.off, tc.length)
			require.Equal(t, wantLen, r.Len(), "Len is the clamped range length")
			require.Equal(t, int64(size), r.Size(), "Size is the whole object")
			require.Equal(t, f.plaintext[tc.off:tc.off+wantLen], got)
		})
	}
}

// TestDecryptRangeA256KW covers the symmetric-KEK unwrapper on the range path, so
// both RecipientUnwrapper implementations are exercised.
func TestDecryptRangeA256KW(t *testing.T) {
	kek := newKEK(t)
	plaintext := patternBytes(2*rangeChunk + 100)
	blob, err := encrypt(t, plaintext, []fee.Recipient{
		fee.NewA256KWRecipient(a256kwKID, kek),
	}, fee.WithChunkSize(rangeChunk))
	require.NoError(t, err)

	off, length := int64(rangeChunk-50), int64(200)
	_, got := decryptRange(t, blob, fee.NewA256KWUnwrapper(a256kwKID, kek), off, length)
	require.Equal(t, plaintext[off:off+length], got)
}

// TestDecryptRangeMixedRecipients confirms the range path picks the recipient
// matching the unwrapper's kid out of a multi-recipient envelope, whichever
// unwrapper the caller holds.
func TestDecryptRangeMixedRecipients(t *testing.T) {
	priv := newX25519Key(t)
	kek := newKEK(t)
	plaintext := patternBytes(2 * rangeChunk)
	blob, err := encrypt(t, plaintext, []fee.Recipient{
		fee.NewECDHESRecipient(ecdhKID, priv.PublicKey()),
		fee.NewA256KWRecipient(a256kwKID, kek),
	}, fee.WithChunkSize(rangeChunk))
	require.NoError(t, err)

	off, length := int64(rangeChunk+11), int64(300)
	for name, u := range map[string]fee.RecipientUnwrapper{
		"ecdh-es": fee.NewECDHESUnwrapper(ecdhKID, priv),
		"a256kw":  fee.NewA256KWUnwrapper(a256kwKID, kek),
	} {
		t.Run(name, func(t *testing.T) {
			_, got := decryptRange(t, blob, u, off, length)
			require.Equal(t, plaintext[off:off+length], got)
		})
	}
}

// TestDecryptRangeWithCEK exercises the external-CEK range path against both
// envelope forms: a COSE_Encrypt whose recipients are ignored, and a
// recipient-less COSE_Encrypt0.
func TestDecryptRangeWithCEK(t *testing.T) {
	cek := newCEK(t)
	plaintext := patternBytes(2*rangeChunk + 77)
	off, length := int64(rangeChunk-20), int64(500)

	t.Run("tag 96 with recipients", func(t *testing.T) {
		blob, err := encryptWithCEK(t, plaintext, cek, []fee.Recipient{
			fee.NewA256KWRecipient(a256kwKID, newKEK(t)),
		}, fee.WithChunkSize(rangeChunk))
		require.NoError(t, err)

		r, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), int64(len(blob)), cek, off, length)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, plaintext[off:off+length], got)
	})

	t.Run("recipient-less tag 16", func(t *testing.T) {
		blob, err := encryptWithCEK(t, plaintext, cek, nil, fee.WithChunkSize(rangeChunk))
		require.NoError(t, err)
		tag, err := cose.PeekTag(blob)
		require.NoError(t, err)
		require.Equal(t, cose.TagCOSEEncrypt0, tag)

		r, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), int64(len(blob)), cek, off, length)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, plaintext[off:off+length], got)
		require.Equal(t, int64(len(plaintext)), r.Size())
	})
}

// TestDecryptRangeReadsOnlySpan is the acceptance criterion that a range read
// fetches only the envelope header and the overlapping ciphertext chunks: it
// records every ReadAt and asserts nothing outside the header probe and the
// reported span was ever touched, and that the chunks flanking the range were
// left alone.
func TestDecryptRangeReadsOnlySpan(t *testing.T) {
	const size = 8 * rangeChunk
	f := newRangeFixture(t, size)

	// A range wholly inside chunk 4 of 8, so there are untouched chunks on both
	// sides and the span is a small fraction of the blob.
	off, length := int64(4*rangeChunk+10), int64(100)

	rec := newRecordingReaderAt(t, f.blob)
	r, err := fee.DecryptRange(rec, int64(len(f.blob)), f.unwrapper, off, length)
	require.NoError(t, err)

	spanOff, spanLen := r.CiphertextSpan()
	headerReads := slices.Clone(rec.reads)
	require.NotEmpty(t, headerReads, "the header must be read at construction")
	for _, rd := range headerReads {
		require.Equal(t, int64(0), rd.off, "construction reads only the header prefix at offset 0")
	}
	require.Less(t, spanLen, int64(len(f.blob))/2, "the span must be far smaller than the blob")

	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, f.plaintext[off:off+length], got)

	// Exactly the reported span was fetched: one chunk's worth, no more.
	require.Equal(t, int64(rangeChunk+aesstream.TagSize), spanLen, "one full ciphertext chunk")

	// Every ciphertext read lies inside the reported span, and together they
	// cover it exactly once.
	var fetched int64
	for _, rd := range rec.reads {
		if rd.off == 0 {
			continue // header probe
		}
		require.GreaterOrEqual(t, rd.off, spanOff, "read before the span start")
		require.LessOrEqual(t, rd.off+rd.n, spanOff+spanLen, "read past the span end")
		fetched += rd.n
	}
	require.Equal(t, spanLen, fetched, "the span is fetched exactly once, in full")
}

// TestDecryptRangeZeroLengthReadsNoCiphertext confirms an empty range is valid,
// reports the object size, and fetches no ciphertext at all — the cheap way for a
// caller to learn a size while holding unwrap material.
func TestDecryptRangeZeroLengthReadsNoCiphertext(t *testing.T) {
	const size = 4 * rangeChunk
	f := newRangeFixture(t, size)

	for _, off := range []int64{0, rangeChunk + 1, size} {
		rec := newRecordingReaderAt(t, f.blob)
		r, err := fee.DecryptRange(rec, int64(len(f.blob)), f.unwrapper, off, 0)
		require.NoError(t, err)

		_, spanLen := r.CiphertextSpan()
		require.Zero(t, spanLen, "an empty range needs no ciphertext")
		require.Zero(t, r.Len())
		require.Equal(t, int64(size), r.Size())

		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Empty(t, got)

		for _, rd := range rec.reads {
			require.Equal(t, int64(0), rd.off, "only the header prefix is read")
		}
	}
}

// TestDecryptRangePrefetchSpan demonstrates the documented prefetch pattern: the
// caller constructs the reader (header I/O only), fetches the reported span in one
// go, and serves the reads from that buffer — after which the origin is never
// touched again.
func TestDecryptRangePrefetchSpan(t *testing.T) {
	const size = 6 * rangeChunk
	f := newRangeFixture(t, size)
	off, length := int64(2*rangeChunk+5), int64(2*rangeChunk)

	rec := newRecordingReaderAt(t, f.blob)
	plan, err := fee.DecryptRange(rec, int64(len(f.blob)), f.unwrapper, off, length)
	require.NoError(t, err)
	spanOff, spanLen := plan.CiphertextSpan()

	// One "range request" for the whole span.
	span := make([]byte, spanLen)
	_, err = rec.ReadAt(span, spanOff)
	require.NoError(t, err)

	// Re-decrypt against a blob view backed by the prefetched span, and prove the
	// origin serves nothing further.
	rec.reject = true
	r, err := fee.DecryptRange(newPrefetchedBlob(f.blob[:spanOff], span, spanOff),
		int64(len(f.blob)), f.unwrapper, off, length)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, f.plaintext[off:off+length], got)
}

// prefetchedBlob is an io.ReaderAt that serves the envelope header from one buffer
// and the pre-fetched ciphertext span from another, the shape a caller gets after
// a single range request.
type prefetchedBlob struct {
	header  *bytes.Reader
	span    *bytes.Reader
	spanOff int64
}

func newPrefetchedBlob(header, span []byte, spanOff int64) prefetchedBlob {
	return prefetchedBlob{header: bytes.NewReader(header), span: bytes.NewReader(span), spanOff: spanOff}
}

func (b prefetchedBlob) ReadAt(p []byte, off int64) (int, error) {
	if off < b.spanOff {
		return b.header.ReadAt(p, off)
	}
	return b.span.ReadAt(p, off-b.spanOff)
}

// TestDecryptRangeTamperedChunkInRange is the acceptance criterion that a tampered
// chunk yields an error rather than corrupt plaintext: every byte position of the
// chunk the range sits in is flipped in turn, and each must fail authentication.
func TestDecryptRangeTamperedChunkInRange(t *testing.T) {
	const size = 3 * rangeChunk
	f := newRangeFixture(t, size)
	off, length := int64(rangeChunk+10), int64(50)

	headerLen := headerLenOf(f.blob, size)
	// Positions inside chunk 1's ciphertext: its first byte, a byte covering the
	// requested range, and a byte of its authentication tag.
	chunkStart := headerLen + int64(rangeChunk+aesstream.TagSize)
	for _, pos := range []int64{
		chunkStart,
		chunkStart + 10,
		chunkStart + int64(rangeChunk) + aesstream.TagSize - 1,
	} {
		tampered := bytes.Clone(f.blob)
		tampered[pos] ^= 0x01

		r, err := fee.DecryptRange(bytes.NewReader(tampered), int64(len(tampered)), f.unwrapper, off, length)
		require.NoError(t, err, "construction only reads the header, so it still succeeds")
		got, err := io.ReadAll(r)
		require.Error(t, err, "a tampered chunk must not decrypt")
		require.ErrorIs(t, err, aesstream.ErrCorrupted)
		require.NotEqual(t, f.plaintext[off:off+length], got, "no corrupt plaintext is returned")
	}
}

// TestDecryptRangeTamperOutsideRange documents the authentication scope: chunks
// the range does not overlap are never fetched, so tampering there cannot be
// detected by (and does not disturb) a range read. Whole-object integrity is the
// caller's concern, per the DecryptRange docs.
func TestDecryptRangeTamperOutsideRange(t *testing.T) {
	const size = 4 * rangeChunk
	f := newRangeFixture(t, size)
	off, length := int64(10), int64(100) // wholly inside chunk 0

	headerLen := headerLenOf(f.blob, size)
	tampered := bytes.Clone(f.blob)
	tampered[headerLen+int64(3*(rangeChunk+aesstream.TagSize))+5] ^= 0x01 // chunk 3

	r, err := fee.DecryptRange(bytes.NewReader(tampered), int64(len(tampered)), f.unwrapper, off, length)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, f.plaintext[off:off+length], got)

	// The same blob fails a whole-object decrypt, which does see chunk 3.
	full, err := fee.Decrypt(bytes.NewReader(tampered), f.unwrapper)
	require.NoError(t, err)
	_, err = io.ReadAll(full)
	require.ErrorIs(t, err, aesstream.ErrCorrupted)
}

// TestDecryptRangeKidMismatch is the acceptance criterion that a kid matching no
// recipient is a clear error rather than a silent failure or a panic.
func TestDecryptRangeKidMismatch(t *testing.T) {
	f := newRangeFixture(t, 2*rangeChunk)

	for name, u := range map[string]fee.RecipientUnwrapper{
		"unknown kid": fee.NewECDHESUnwrapper([]byte("did:key:zNobody#key-1"), newX25519Key(t)),
		"empty kid":   fee.NewECDHESUnwrapper(nil, newX25519Key(t)),
		"right kid, wrong wrap algorithm": fee.NewA256KWUnwrapper(
			[]byte("did:example:custody#absent"), newKEK(t)),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := fee.DecryptRange(bytes.NewReader(f.blob), int64(len(f.blob)), u, 0, 100)
			require.ErrorIs(t, err, fee.ErrNoMatchingRecipient)
			require.Nil(t, r)
		})
	}
}

// TestDecryptRangeWrongKey confirms a matched recipient whose CEK cannot be
// recovered fails at construction, with no reader handed back — parity with the
// whole-object path.
func TestDecryptRangeWrongKey(t *testing.T) {
	t.Run("ecdh-es", func(t *testing.T) {
		f := newRangeFixture(t, 2*rangeChunk)
		wrong := fee.NewECDHESUnwrapper(ecdhKID, newX25519Key(t))
		r, err := fee.DecryptRange(bytes.NewReader(f.blob), int64(len(f.blob)), wrong, 0, 100)
		require.Error(t, err)
		require.Nil(t, r)
	})

	t.Run("a256kw", func(t *testing.T) {
		plaintext := patternBytes(2 * rangeChunk)
		blob, err := encrypt(t, plaintext, []fee.Recipient{
			fee.NewA256KWRecipient(a256kwKID, newKEK(t)),
		}, fee.WithChunkSize(rangeChunk))
		require.NoError(t, err)

		wrong := fee.NewA256KWUnwrapper(a256kwKID, newKEK(t))
		r, err := fee.DecryptRange(bytes.NewReader(blob), int64(len(blob)), wrong, 0, 100)
		require.Error(t, err)
		require.Nil(t, r)
	})
}

// TestDecryptRangeEncrypt0NeedsCEK confirms a recipient-less envelope steers the
// caller to DecryptRangeWithCEK rather than failing obscurely.
func TestDecryptRangeEncrypt0NeedsCEK(t *testing.T) {
	cek := newCEK(t)
	blob, err := encryptWithCEK(t, patternBytes(rangeChunk), cek, nil, fee.WithChunkSize(rangeChunk))
	require.NoError(t, err)

	r, err := fee.DecryptRange(bytes.NewReader(blob), int64(len(blob)),
		fee.NewA256KWUnwrapper(a256kwKID, newKEK(t)), 0, 100)
	require.ErrorIs(t, err, fee.ErrNoRecipientsInEnvelope)
	require.Nil(t, r)
}

// TestDecryptRangeInvalidArgs covers the argument checks that must fire before any
// I/O or key handling.
func TestDecryptRangeInvalidArgs(t *testing.T) {
	f := newRangeFixture(t, rangeChunk)
	size := int64(len(f.blob))

	t.Run("nil blob", func(t *testing.T) {
		_, err := fee.DecryptRange(nil, size, f.unwrapper, 0, 10)
		require.Error(t, err)
		_, err = fee.DecryptRangeWithCEK(nil, size, newCEK(t), 0, 10)
		require.Error(t, err)
	})

	t.Run("nil unwrapper", func(t *testing.T) {
		_, err := fee.DecryptRange(bytes.NewReader(f.blob), size, nil, 0, 10)
		require.ErrorIs(t, err, fee.ErrNilUnwrapper)
	})

	t.Run("cek wrong length", func(t *testing.T) {
		_, err := fee.DecryptRangeWithCEK(bytes.NewReader(f.blob), size, make([]byte, 16), 0, 10)
		require.ErrorIs(t, err, fee.ErrInvalidCEK)
	})

	t.Run("negative blob size", func(t *testing.T) {
		_, err := fee.DecryptRange(bytes.NewReader(f.blob), -1, f.unwrapper, 0, 10)
		require.Error(t, err)
		_, err = fee.PlaintextSize(bytes.NewReader(f.blob), -1)
		require.Error(t, err)
	})
}

// TestDecryptRangeBounds pins the out-of-bounds and clamping semantics an HTTP
// range consumer depends on: a bad range is reported as aesstream.ErrRange (a
// 416), an offset at the end is a legal empty read, and an overlong length clamps.
func TestDecryptRangeBounds(t *testing.T) {
	const size = 2*rangeChunk + 10
	f := newRangeFixture(t, size)
	blobSize := int64(len(f.blob))

	t.Run("rejected", func(t *testing.T) {
		for name, rg := range map[string]struct{ off, length int64 }{
			"negative offset": {-1, 10},
			"negative length": {0, -1},
			"offset past end": {size + 1, 10},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := fee.DecryptRange(bytes.NewReader(f.blob), blobSize, f.unwrapper, rg.off, rg.length)
				require.ErrorIs(t, err, aesstream.ErrRange)
			})
		}
	})

	t.Run("offset at end is empty", func(t *testing.T) {
		for _, length := range []int64{0, 100} {
			r, got := decryptRange(t, f.blob, f.unwrapper, size, length)
			require.Zero(t, r.Len())
			require.Empty(t, got)
			require.Equal(t, int64(size), r.Size())
		}
	})

	t.Run("length clamps to the end", func(t *testing.T) {
		r, got := decryptRange(t, f.blob, f.unwrapper, size-5, math.MaxInt64)
		require.Equal(t, int64(5), r.Len())
		require.Equal(t, f.plaintext[size-5:], got)
	})
}

// TestDecryptRangeGeometryCorners covers the object sizes whose chunk geometry is
// degenerate: an empty plaintext (a single empty final chunk) and an object of
// exactly one full chunk.
func TestDecryptRangeGeometryCorners(t *testing.T) {
	t.Run("empty plaintext", func(t *testing.T) {
		f := newRangeFixture(t, 0)
		r, got := decryptRange(t, f.blob, f.unwrapper, 0, 100)
		require.Zero(t, r.Len())
		require.Zero(t, r.Size())
		require.Empty(t, got)

		_, err := fee.DecryptRange(bytes.NewReader(f.blob), int64(len(f.blob)), f.unwrapper, 1, 1)
		require.ErrorIs(t, err, aesstream.ErrRange)
	})

	t.Run("exactly one chunk", func(t *testing.T) {
		f := newRangeFixture(t, rangeChunk)
		r, got := decryptRange(t, f.blob, f.unwrapper, 0, rangeChunk)
		require.Equal(t, int64(rangeChunk), r.Size())
		require.Equal(t, f.plaintext, got)

		_, tail := decryptRange(t, f.blob, f.unwrapper, rangeChunk-1, 1)
		require.Equal(t, f.plaintext[rangeChunk-1:], tail)
	})

	t.Run("one byte over a chunk", func(t *testing.T) {
		f := newRangeFixture(t, rangeChunk+1)
		_, got := decryptRange(t, f.blob, f.unwrapper, rangeChunk, 1)
		require.Equal(t, f.plaintext[rangeChunk:], got)
	})
}

// TestDecryptRangeChunkCountMismatch confirms the advisory consistency check: when
// the envelope records a chunk count, a blob size implying a different count is
// refused up front rather than silently serving a truncated view of the object.
func TestDecryptRangeChunkCountMismatch(t *testing.T) {
	const size = 4 * rangeChunk
	f := newRangeFixture(t, size, fee.WithContentLength(size))
	blobSize := int64(len(f.blob))
	encChunk := int64(rangeChunk + aesstream.TagSize)

	for name, claimed := range map[string]int64{
		"one chunk short": blobSize - encChunk,
		"one chunk long":  blobSize + encChunk,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fee.DecryptRange(bytes.NewReader(f.blob), claimed, f.unwrapper, 0, 100)
			require.ErrorIs(t, err, fee.ErrSizeMismatch)

			_, err = fee.PlaintextSize(bytes.NewReader(f.blob), claimed)
			require.ErrorIs(t, err, fee.ErrSizeMismatch)
		})
	}

	t.Run("correct size still works", func(t *testing.T) {
		_, got := decryptRange(t, f.blob, f.unwrapper, rangeChunk, 100)
		require.Equal(t, f.plaintext[rangeChunk:rangeChunk+100], got)
	})
}

// TestDecryptRangeWrongBlobSizeNoChunkCount pins the documented trust model for an
// envelope with no chunk count: a wrong blob size cannot be caught at construction,
// so it surfaces as a failure to authenticate when the affected chunks are read.
func TestDecryptRangeWrongBlobSizeNoChunkCount(t *testing.T) {
	const size = 4 * rangeChunk
	f := newRangeFixture(t, size) // no WithContentLength, so no chunk count
	blobSize := int64(len(f.blob))
	encChunk := int64(rangeChunk + aesstream.TagSize)

	t.Run("overstated size", func(t *testing.T) {
		// The geometry says the object is a chunk longer than it is, so a range
		// at the claimed end either runs off the end of the blob or reads a chunk
		// under the wrong index and last-chunk flag. Either way it fails rather
		// than emitting plaintext.
		r, err := fee.DecryptRange(bytes.NewReader(f.blob), blobSize+encChunk, f.unwrapper, size-10, 100)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.Error(t, err)
		require.True(t, errors.Is(err, aesstream.ErrShortSpan) || errors.Is(err, aesstream.ErrCorrupted),
			"want a short-span or authentication failure, got %v", err)
		require.NotEqual(t, f.plaintext[size-10:], got)
	})

	t.Run("understated size mislabels the final chunk", func(t *testing.T) {
		// One chunk short: chunk 2 is now believed final, so its nonce carries
		// the last-chunk flag and authentication fails.
		r, err := fee.DecryptRange(bytes.NewReader(f.blob), blobSize-encChunk, f.unwrapper,
			int64(2*rangeChunk), 100)
		require.NoError(t, err)
		_, err = io.ReadAll(r)
		require.ErrorIs(t, err, aesstream.ErrCorrupted)
	})
}

// TestDecryptRangeInvalidBlobSize covers blob sizes that cannot describe a FEE
// stream at all, independent of any chunk count.
func TestDecryptRangeInvalidBlobSize(t *testing.T) {
	f := newRangeFixture(t, rangeChunk)
	blobSize := int64(len(f.blob))

	// A blob claiming fewer bytes than the envelope plus one tag leaves a
	// ciphertext too short to be a stream.
	_, err := fee.DecryptRange(bytes.NewReader(f.blob), blobSize-int64(rangeChunk)-aesstream.TagSize,
		f.unwrapper, 0, 10)
	require.ErrorIs(t, err, aesstream.ErrCiphertextSize)
}

// TestDecryptRangeMalformedBlob confirms a blob that is not a FEE envelope is
// rejected on its own terms — with the cose sentinel a caller can classify —
// before any key material is touched.
func TestDecryptRangeMalformedBlob(t *testing.T) {
	f := newRangeFixture(t, rangeChunk)

	for name, tc := range map[string]struct {
		blob []byte
		want error
	}{
		"empty blob":     {[]byte{}, cose.ErrMalformed},
		"truncated blob": {f.blob[:3], cose.ErrMalformed},
		// A well-formed CBOR item that is not a tag: decodable, but not a COSE
		// envelope.
		"not a cose tag": {[]byte{0x01, 0x02, 0x03}, cose.ErrNotEncrypt},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fee.DecryptRange(bytes.NewReader(tc.blob), int64(len(tc.blob)), f.unwrapper, 0, 10)
			require.ErrorIs(t, err, tc.want)

			_, err = fee.PlaintextSize(bytes.NewReader(tc.blob), int64(len(tc.blob)))
			require.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("random bytes", func(t *testing.T) {
		garbage := make([]byte, 512)
		_, err := rand.Read(garbage)
		require.NoError(t, err)
		// Random bytes are rejected either as un-decodable CBOR or as a
		// well-formed item that is not a COSE tag, depending on the first byte.
		_, err = fee.DecryptRange(bytes.NewReader(garbage), int64(len(garbage)), f.unwrapper, 0, 10)
		require.Error(t, err)
		require.True(t, errors.Is(err, cose.ErrMalformed) || errors.Is(err, cose.ErrNotEncrypt),
			"want a cose decode error, got %v", err)
	})

	t.Run("header truncated mid-envelope", func(t *testing.T) {
		// A blob size that stops inside the envelope: the probe cannot complete a
		// decode and must report it rather than looping.
		_, err := fee.DecryptRange(bytes.NewReader(f.blob), 20, f.unwrapper, 0, 10)
		require.ErrorIs(t, err, cose.ErrMalformed)
	})
}

// TestDecryptRangeMalformedBlobReadsOnce pins that a blob whose leading bytes
// decode completely but are not a FEE envelope is rejected on the strength of the
// first read. Only a prefix cut short mid-item can be answered by reading more, so
// a wrong object id costs one 4 KiB read rather than a walk up to maxHeaderLen
// against the origin.
func TestDecryptRangeMalformedBlobReadsOnce(t *testing.T) {
	f := newRangeFixture(t, rangeChunk)

	// Each prefix is a complete CBOR item, so no larger read can change the
	// verdict; the trailing zeroes stand in for a large stored object.
	for name, tc := range map[string]struct {
		prefix string
		want   error
	}{
		// A bare integer: a whole item, but not a tag.
		"not a cose tag": {"01", cose.ErrNotEncrypt},
		// Tag 96 wrapping a 3-element array, where 4 are required.
		"wrong array length": {"d8608340a0f6", cose.ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			blob := make([]byte, 10<<20)
			copy(blob, hexBytes(t, tc.prefix))

			rec := newRecordingReaderAt(t, blob)
			_, err := fee.DecryptRange(rec, int64(len(blob)), f.unwrapper, 0, 10)
			require.ErrorIs(t, err, tc.want)
			require.Len(t, rec.reads, 1, "a complete but invalid prefix must not be re-read")
		})
	}
}

// TestDecryptRangeLargeEnvelope exercises the header probe's growth path: with
// enough recipients the envelope exceeds the first probe size, and the probe must
// still recover the exact header length so the ciphertext is located correctly.
func TestDecryptRangeLargeEnvelope(t *testing.T) {
	const recipients = 64
	priv := newX25519Key(t)
	rs := []fee.Recipient{fee.NewECDHESRecipient(ecdhKID, priv.PublicKey())}
	for i := 0; i < recipients; i++ {
		other, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		rs = append(rs, fee.NewECDHESRecipient([]byte("did:key:filler#key-"+string(rune('a'+i%26))+string(rune('a'+i/26))), other.PublicKey()))
	}

	const size = 2 * rangeChunk
	plaintext := patternBytes(size)
	blob, err := encrypt(t, plaintext, rs, fee.WithChunkSize(rangeChunk))
	require.NoError(t, err)

	require.Greater(t, headerLenOf(blob, size), int64(4096), "the envelope must exceed the first probe size")

	off, length := int64(rangeChunk+7), int64(300)
	_, got := decryptRange(t, blob, fee.NewECDHESUnwrapper(ecdhKID, priv), off, length)
	require.Equal(t, plaintext[off:off+length], got)
}

// TestPlaintextSize confirms the header-only size query matches the real plaintext
// length across geometries, without key material.
func TestPlaintextSize(t *testing.T) {
	for _, size := range []int{0, 1, rangeChunk - 1, rangeChunk, rangeChunk + 1, 3*rangeChunk + 100} {
		f := newRangeFixture(t, size)
		got, err := fee.PlaintextSize(bytes.NewReader(f.blob), int64(len(f.blob)))
		require.NoError(t, err)
		require.Equal(t, int64(size), got, "plaintext size for a %d-byte object", size)
	}

	t.Run("reads only the header", func(t *testing.T) {
		f := newRangeFixture(t, 8*rangeChunk)
		rec := newRecordingReaderAt(t, f.blob)
		_, err := fee.PlaintextSize(rec, int64(len(f.blob)))
		require.NoError(t, err)
		for _, rd := range rec.reads {
			require.Equal(t, int64(0), rd.off)
			require.LessOrEqual(t, rd.n, int64(4096))
		}
	})
}

// TestDecryptRangeMatchesFullDecrypt cross-checks the range path against the
// whole-object path: for a set of ranges over the same blob, range decryption must
// agree byte-for-byte with the corresponding slice of a full Decrypt.
func TestDecryptRangeMatchesFullDecrypt(t *testing.T) {
	const size = 5*rangeChunk + 123
	f := newRangeFixture(t, size, fee.WithContentLength(size))

	full := decryptAll(t, f.blob, f.unwrapper)
	require.Equal(t, f.plaintext, full)

	for _, rg := range []struct{ off, length int64 }{
		{0, 1}, {1, rangeChunk}, {rangeChunk - 1, 2}, {2 * rangeChunk, 3 * rangeChunk},
		{5 * rangeChunk, 123}, {size - 1, 1},
	} {
		_, got := decryptRange(t, f.blob, f.unwrapper, rg.off, rg.length)
		require.Equal(t, full[rg.off:rg.off+int64(len(got))], got)
	}
}
