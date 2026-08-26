package fee_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
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

// sealTrailingEmptyFinalChunk builds a FEE blob whose ciphertext is k full
// chunks followed by an empty final chunk, declared as k+1 — the second valid
// encoding of a plaintext that is an exact multiple of the chunk size.
//
// aesstream.Writer never emits this form (it flushes a full buffer as the final
// chunk, giving k), so the body is sealed chunk by chunk here, under the
// documented per-chunk nonce and the envelope's own Enc_structure as AAD.
func sealTrailingEmptyFinalChunk(t *testing.T, plaintext, cek, baseNonce []byte, chunkSize int) []byte {
	t.Helper()
	require.Zero(t, len(plaintext)%chunkSize, "plaintext must be an exact multiple of the chunk size")
	chunks := len(plaintext)/chunkSize + 1 // the trailing empty chunk is the extra one

	env := &cose.Envelope{Headers: cose.Headers{
		Protected: cose.Header{}.
			Set(cose.HeaderLabelAlg, algChunkedStream).
			Set(cose.HeaderLabelType, fee.EnvelopeType),
		Unprotected: cose.Header{}.
			Set(cose.HeaderLabelIV, baseNonce).
			Set(labelChunkSize, int64(chunkSize)).
			Set(labelChunkCount, int64(chunks)),
	}}
	aad, err := env.EncStructure(nil)
	require.NoError(t, err)
	header, err := env.Encode()
	require.NoError(t, err)

	block, err := aes.NewCipher(cek)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	blob := bytes.Clone(header)
	for i := range chunks {
		last := i == chunks-1
		var chunk []byte
		if !last {
			chunk = plaintext[i*chunkSize : (i+1)*chunkSize]
		}
		blob = aead.Seal(blob, streamNonce(baseNonce, i, last), chunk, aad)
	}
	return blob
}

// streamNonce builds the per-chunk GCM nonce of the FEE body cipher:
// baseNonce(7) || chunkIndex(4, big-endian) || lastFlag(1).
func streamNonce(baseNonce []byte, index int, last bool) []byte {
	nonce := make([]byte, 0, aesstream.NonceSize)
	nonce = append(nonce, baseNonce...)
	nonce = binary.BigEndian.AppendUint32(nonce, uint32(index))
	if last {
		return append(nonce, 0x01)
	}
	return append(nonce, 0x00)
}

// hexBytes decodes a hex literal, for the handful of tests that pin behaviour
// against exact wire bytes rather than an encrypted fixture.
func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// clampLen is the plaintext length an inclusive range request [start, end]
// actually yields from a size-byte object: end clamps to the last byte, so an
// open-ended math.MaxInt64 end cannot overflow the length.
func clampLen(size, start, end int64) int64 {
	return min(end, size-1) - start + 1
}

// headerLenOf reports the encoded envelope length of a blob holding size
// plaintext bytes at rangeChunk, by subtracting the ciphertext the STREAM
// geometry accounts for.
func headerLenOf(blob []byte, size int64) int64 {
	return int64(len(blob)) - aesstream.EncryptedSize(size, rangeChunk)
}

// decryptRange range-decrypts the inclusive range [start, end] from blob and
// returns the reader alongside the bytes it emitted, asserting a clean stream.
func decryptRange(t *testing.T, blob []byte, u fee.RecipientUnwrapper, start, end int64) (*fee.RangeReader, []byte) {
	t.Helper()
	r, err := fee.DecryptRange(bytes.NewReader(blob), int64(len(blob)), u, start, end)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	return r, got
}

// TestDecryptRangeRoundTrip is the acceptance criterion that one call with an
// envelope, unwrap material and a byte range returns exactly the requested
// plaintext — across the interesting geometries of a multi-chunk object: whole
// object, within one chunk, spanning a boundary, exactly one aligned chunk, into
// the final chunk, and single bytes at each end. It runs the whole set against
// both object shapes, since the final chunk being full rather than short is the
// corner the declared chunk count is ambiguous at.
func TestDecryptRangeRoundTrip(t *testing.T) {
	t.Run("partial final chunk", func(t *testing.T) {
		testRangeRoundTrip(t, 3*rangeChunk+rangeChunk/2)
	})

	// An exact multiple of the chunk size: the final chunk is full rather than
	// short, the geometry corner the wire format's chunk count is ambiguous at.
	t.Run("exact multiple of the chunk size", func(t *testing.T) {
		testRangeRoundTrip(t, 4*rangeChunk)
	})
}

func testRangeRoundTrip(t *testing.T, size int64) {
	t.Helper()
	f := newRangeFixture(t, int(size), fee.WithContentLength(size))

	cases := []struct {
		name       string
		start, end int64
	}{
		{"whole object", 0, size - 1},
		{"first byte", 0, 0},
		{"last byte", size - 1, size - 1},
		{"within first chunk", 100, 599},
		{"within middle chunk", rangeChunk + 7, rangeChunk + 1006},
		{"across one boundary", rangeChunk - 10, rangeChunk + 9},
		{"across two boundaries", rangeChunk - 10, 3*rangeChunk + 9},
		{"exactly one aligned chunk", rangeChunk, 2*rangeChunk - 1},
		{"aligned start, unaligned end", 2 * rangeChunk, 3*rangeChunk + 4},
		{"from the last chunk's start", 3 * rangeChunk, 3*rangeChunk + rangeChunk/2 - 1},
		{"into final chunk", 3*rangeChunk - 5, 3*rangeChunk + 94},
		{"ends exactly on boundary", rangeChunk / 2, rangeChunk - 1},
		{"end past last byte clamps", size - 10, size + 989},
		{"open-ended range clamps", rangeChunk, math.MaxInt64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, got := decryptRange(t, f.blob, f.unwrapper, tc.start, tc.end)

			wantLen := clampLen(size, tc.start, tc.end)
			require.Equal(t, wantLen, r.Len(), "Len is the clamped range length")
			require.Equal(t, size, r.Size(), "Size is the whole object")
			require.Equal(t, f.plaintext[tc.start:tc.start+wantLen], got)
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

	start, end := int64(rangeChunk-50), int64(rangeChunk+149)
	_, got := decryptRange(t, blob, fee.NewA256KWUnwrapper(a256kwKID, kek), start, end)
	require.Equal(t, plaintext[start:end+1], got)
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

	start, end := int64(rangeChunk+11), int64(rangeChunk+310)
	for name, u := range map[string]fee.RecipientUnwrapper{
		"ecdh-es": fee.NewECDHESUnwrapper(ecdhKID, priv),
		"a256kw":  fee.NewA256KWUnwrapper(a256kwKID, kek),
	} {
		t.Run(name, func(t *testing.T) {
			_, got := decryptRange(t, blob, u, start, end)
			require.Equal(t, plaintext[start:end+1], got)
		})
	}
}

// TestDecryptRangeWithCEK exercises the external-CEK range path against both
// envelope forms: a COSE_Encrypt whose recipients are ignored, and a
// recipient-less COSE_Encrypt0.
func TestDecryptRangeWithCEK(t *testing.T) {
	cek := newCEK(t)
	plaintext := patternBytes(2*rangeChunk + 77)
	start, end := int64(rangeChunk-20), int64(rangeChunk+479)

	t.Run("tag 96 with recipients", func(t *testing.T) {
		blob, err := encryptWithCEK(t, plaintext, cek, []fee.Recipient{
			fee.NewA256KWRecipient(a256kwKID, newKEK(t)),
		}, fee.WithChunkSize(rangeChunk))
		require.NoError(t, err)

		r, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), int64(len(blob)), cek, start, end, nil)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, plaintext[start:end+1], got)
	})

	t.Run("recipient-less tag 16", func(t *testing.T) {
		blob, err := encryptWithCEK(t, plaintext, cek, nil, fee.WithChunkSize(rangeChunk))
		require.NoError(t, err)
		tag, err := cose.PeekTag(blob)
		require.NoError(t, err)
		require.Equal(t, cose.TagCOSEEncrypt0, tag)

		r, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), int64(len(blob)), cek, start, end, nil)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, plaintext[start:end+1], got)
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
	start, end := int64(4*rangeChunk+10), int64(4*rangeChunk+109)

	rec := newRecordingReaderAt(t, f.blob)
	r, err := fee.DecryptRange(rec, int64(len(f.blob)), f.unwrapper, start, end)
	require.NoError(t, err)

	spanStart, spanEnd := r.CiphertextSpan()
	spanLen := spanEnd - spanStart + 1
	headerReads := slices.Clone(rec.reads)
	require.NotEmpty(t, headerReads, "the header must be read at construction")
	for _, rd := range headerReads {
		require.Equal(t, int64(0), rd.off, "construction reads only the header prefix at offset 0")
	}
	require.Less(t, spanLen, int64(len(f.blob))/2, "the span must be far smaller than the blob")

	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, f.plaintext[start:end+1], got)

	// Exactly the reported span was fetched: one chunk's worth, no more.
	require.Equal(t, int64(rangeChunk+aesstream.TagSize), spanLen, "one full ciphertext chunk")

	// Every ciphertext read lies inside the reported span, and together they
	// cover it exactly once.
	var fetched int64
	for _, rd := range rec.reads {
		if rd.off == 0 {
			continue // header probe
		}
		require.GreaterOrEqual(t, rd.off, spanStart, "read before the span start")
		require.LessOrEqual(t, rd.off+rd.n-1, spanEnd, "read past the span end")
		fetched += rd.n
	}
	require.Equal(t, spanLen, fetched, "the span is fetched exactly once, in full")
}

// TestDecryptRangeNoEmptyRange pins that there is no empty range: an end before
// the start, or a start at or past the object's end, is rejected with
// aesstream.ErrRange at construction — after only the header read, with no
// ciphertext ever fetched.
func TestDecryptRangeNoEmptyRange(t *testing.T) {
	const size = 4 * rangeChunk
	f := newRangeFixture(t, size)

	for _, tc := range []struct {
		name       string
		start, end int64
	}{
		{"end before start at the beginning", 0, -1},
		{"end before start in the middle", rangeChunk + 1, rangeChunk},
		{"start at the object's end", size, size},
		{"start past the object's end", size, size + 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRecordingReaderAt(t, f.blob)
			r, err := fee.DecryptRange(rec, int64(len(f.blob)), f.unwrapper, tc.start, tc.end)
			require.ErrorIs(t, err, aesstream.ErrRange)
			require.Nil(t, r)

			for _, rd := range rec.reads {
				require.Equal(t, int64(0), rd.off, "only the header prefix is read")
			}
		})
	}
}

// TestDecryptRangePrefetchSpan demonstrates the documented prefetch pattern: the
// caller constructs the reader (header I/O only), fetches the reported span in one
// go, and serves the reads from that buffer — after which the origin is never
// touched again.
func TestDecryptRangePrefetchSpan(t *testing.T) {
	const size = 6 * rangeChunk
	f := newRangeFixture(t, size)
	start, end := int64(2*rangeChunk+5), int64(4*rangeChunk+4)

	rec := newRecordingReaderAt(t, f.blob)
	plan, err := fee.DecryptRange(rec, int64(len(f.blob)), f.unwrapper, start, end)
	require.NoError(t, err)
	spanStart, spanEnd := plan.CiphertextSpan()

	// One "range request" for the whole span.
	span := make([]byte, spanEnd-spanStart+1)
	_, err = rec.ReadAt(span, spanStart)
	require.NoError(t, err)

	// Re-decrypt against a blob view backed by the prefetched span, and prove the
	// origin serves nothing further.
	rec.reject = true
	r, err := fee.DecryptRange(newPrefetchedBlob(f.blob[:spanStart], span, spanStart),
		int64(len(f.blob)), f.unwrapper, start, end)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, f.plaintext[start:end+1], got)
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
	start, end := int64(rangeChunk+10), int64(rangeChunk+59)

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

		r, err := fee.DecryptRange(bytes.NewReader(tampered), int64(len(tampered)), f.unwrapper, start, end)
		require.NoError(t, err, "construction only reads the header, so it still succeeds")
		got, err := io.ReadAll(r)
		require.Error(t, err, "a tampered chunk must not decrypt")
		require.ErrorIs(t, err, aesstream.ErrCorrupted)
		require.NotEqual(t, f.plaintext[start:end+1], got, "no corrupt plaintext is returned")
	}
}

// TestDecryptRangeTamperOutsideRange documents the authentication scope: chunks
// the range does not overlap are never fetched, so tampering there cannot be
// detected by (and does not disturb) a range read. Whole-object integrity is the
// caller's concern, per the DecryptRange docs.
func TestDecryptRangeTamperOutsideRange(t *testing.T) {
	const size = 4 * rangeChunk
	f := newRangeFixture(t, size)
	start, end := int64(10), int64(109) // wholly inside chunk 0

	headerLen := headerLenOf(f.blob, size)
	tampered := bytes.Clone(f.blob)
	tampered[headerLen+int64(3*(rangeChunk+aesstream.TagSize))+5] ^= 0x01 // chunk 3

	r, err := fee.DecryptRange(bytes.NewReader(tampered), int64(len(tampered)), f.unwrapper, start, end)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, f.plaintext[start:end+1], got)

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
			r, err := fee.DecryptRange(bytes.NewReader(f.blob), int64(len(f.blob)), u, 0, 99)
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
		r, err := fee.DecryptRange(bytes.NewReader(f.blob), int64(len(f.blob)), wrong, 0, 99)
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
		r, err := fee.DecryptRange(bytes.NewReader(blob), int64(len(blob)), wrong, 0, 99)
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
		fee.NewA256KWUnwrapper(a256kwKID, newKEK(t)), 0, 99)
	require.ErrorIs(t, err, fee.ErrNoRecipientsInEnvelope)
	require.Nil(t, r)
}

// TestDecryptRangeInvalidArgs covers the argument checks that must fire before any
// I/O or key handling.
func TestDecryptRangeInvalidArgs(t *testing.T) {
	f := newRangeFixture(t, rangeChunk)
	size := int64(len(f.blob))

	t.Run("nil blob", func(t *testing.T) {
		_, err := fee.DecryptRange(nil, size, f.unwrapper, 0, 9)
		require.Error(t, err)
		_, err = fee.DecryptRangeWithCEK(nil, size, newCEK(t), 0, 9, nil)
		require.Error(t, err)
	})

	t.Run("nil unwrapper", func(t *testing.T) {
		_, err := fee.DecryptRange(bytes.NewReader(f.blob), size, nil, 0, 9)
		require.ErrorIs(t, err, fee.ErrNilUnwrapper)
	})

	t.Run("cek wrong length", func(t *testing.T) {
		_, err := fee.DecryptRangeWithCEK(bytes.NewReader(f.blob), size, make([]byte, 16), 0, 9, nil)
		require.ErrorIs(t, err, fee.ErrInvalidCEK)
	})

	t.Run("negative blob size", func(t *testing.T) {
		_, err := fee.DecryptRange(bytes.NewReader(f.blob), -1, f.unwrapper, 0, 9)
		require.Error(t, err)
		_, err = fee.PlaintextSize(bytes.NewReader(f.blob), -1)
		require.Error(t, err)
	})
}

// TestDecryptRangeBounds pins the out-of-bounds and clamping semantics an HTTP
// range consumer depends on: an unsatisfiable range — a negative start, an end
// before the start, or a start at or past the object's end — is reported as
// aesstream.ErrRange (a 416), and an end past the last byte clamps.
func TestDecryptRangeBounds(t *testing.T) {
	const size = 2*rangeChunk + 10
	f := newRangeFixture(t, size)
	blobSize := int64(len(f.blob))

	t.Run("rejected", func(t *testing.T) {
		for name, rg := range map[string]struct{ start, end int64 }{
			"negative start":   {-1, 8},
			"end before start": {10, 9},
			"start at end":     {size, size + 99},
			"start past end":   {size + 1, size + 10},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := fee.DecryptRange(bytes.NewReader(f.blob), blobSize, f.unwrapper, rg.start, rg.end)
				require.ErrorIs(t, err, aesstream.ErrRange)
			})
		}
	})

	t.Run("end clamps to the last byte", func(t *testing.T) {
		r, got := decryptRange(t, f.blob, f.unwrapper, size-5, math.MaxInt64)
		require.Equal(t, int64(5), r.Len())
		require.Equal(t, f.plaintext[size-5:], got)
	})
}

// TestDecryptRangeGeometryCorners covers the object sizes whose chunk geometry is
// degenerate: an empty plaintext (a single empty final chunk, with no byte any
// range could address) and an object of exactly one full chunk.
func TestDecryptRangeGeometryCorners(t *testing.T) {
	t.Run("empty plaintext", func(t *testing.T) {
		f := newRangeFixture(t, 0)
		// An empty object has no addressable byte, so every range is out of
		// bounds; its size is still available via PlaintextSize.
		_, err := fee.DecryptRange(bytes.NewReader(f.blob), int64(len(f.blob)), f.unwrapper, 0, 0)
		require.ErrorIs(t, err, aesstream.ErrRange)

		_, err = fee.DecryptRange(bytes.NewReader(f.blob), int64(len(f.blob)), f.unwrapper, 1, 1)
		require.ErrorIs(t, err, aesstream.ErrRange)
	})

	t.Run("exactly one chunk", func(t *testing.T) {
		f := newRangeFixture(t, rangeChunk)
		r, got := decryptRange(t, f.blob, f.unwrapper, 0, rangeChunk-1)
		require.Equal(t, int64(rangeChunk), r.Size())
		require.Equal(t, f.plaintext, got)

		_, tail := decryptRange(t, f.blob, f.unwrapper, rangeChunk-1, rangeChunk-1)
		require.Equal(t, f.plaintext[rangeChunk-1:], tail)
	})

	t.Run("one byte over a chunk", func(t *testing.T) {
		f := newRangeFixture(t, rangeChunk+1)
		_, got := decryptRange(t, f.blob, f.unwrapper, rangeChunk, rangeChunk)
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
			_, err := fee.DecryptRange(bytes.NewReader(f.blob), claimed, f.unwrapper, 0, 99)
			require.ErrorIs(t, err, fee.ErrSizeMismatch)

			_, err = fee.PlaintextSize(bytes.NewReader(f.blob), claimed)
			require.ErrorIs(t, err, fee.ErrSizeMismatch)
		})
	}

	t.Run("correct size still works", func(t *testing.T) {
		_, got := decryptRange(t, f.blob, f.unwrapper, rangeChunk, rangeChunk+99)
		require.Equal(t, f.plaintext[rangeChunk:rangeChunk+100], got)
	})
}

// TestDecryptRangeTrailingEmptyFinalChunk pins that the range path accepts the
// second valid encoding of an exact-multiple plaintext: k full chunks followed by
// an empty final chunk, declared as k+1. aesstream reads that layout and so does
// whole-object decryption, so the range entry points must agree rather than
// refusing a blob the rest of the package accepts.
func TestDecryptRangeTrailingEmptyFinalChunk(t *testing.T) {
	const size = 3 * rangeChunk
	cek, plaintext := newCEK(t), patternBytes(size)
	baseNonce := bytes.Repeat([]byte{0xa5}, aesstream.BaseNonceSize)
	blob := sealTrailingEmptyFinalChunk(t, plaintext, cek, baseNonce, rangeChunk)
	blobSize := int64(len(blob))

	// The premise: whole-object decryption already reads this blob.
	whole, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
	require.NoError(t, err)
	got, err := io.ReadAll(whole)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)

	t.Run("PlaintextSize agrees", func(t *testing.T) {
		n, err := fee.PlaintextSize(bytes.NewReader(blob), blobSize)
		require.NoError(t, err)
		require.Equal(t, int64(size), n)
	})

	t.Run("range across the last full chunk", func(t *testing.T) {
		start, end := int64(2*rangeChunk-10), int64(2*rangeChunk+9)
		r, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), blobSize, cek, start, end, nil)
		require.NoError(t, err)
		require.Equal(t, int64(size), r.Size())
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, plaintext[start:end+1], got)
	})

	t.Run("whole object as one range", func(t *testing.T) {
		r, err := fee.DecryptRangeWithCEK(bytes.NewReader(blob), blobSize, cek, 0, size-1, nil)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
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
		r, err := fee.DecryptRange(bytes.NewReader(f.blob), blobSize+encChunk, f.unwrapper, size-10, size+89)
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
			int64(2*rangeChunk), int64(2*rangeChunk+99))
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
		f.unwrapper, 0, 9)
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
			_, err := fee.DecryptRange(bytes.NewReader(tc.blob), int64(len(tc.blob)), f.unwrapper, 0, 9)
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
		_, err = fee.DecryptRange(bytes.NewReader(garbage), int64(len(garbage)), f.unwrapper, 0, 9)
		require.Error(t, err)
		require.True(t, errors.Is(err, cose.ErrMalformed) || errors.Is(err, cose.ErrNotEncrypt),
			"want a cose decode error, got %v", err)
	})

	t.Run("header truncated mid-envelope", func(t *testing.T) {
		// A blob size that stops inside the envelope: the probe cannot complete a
		// decode and must report it rather than looping.
		_, err := fee.DecryptRange(bytes.NewReader(f.blob), 20, f.unwrapper, 0, 9)
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
			_, err := fee.DecryptRange(rec, int64(len(blob)), f.unwrapper, 0, 9)
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

	start, end := int64(rangeChunk+7), int64(rangeChunk+306)
	_, got := decryptRange(t, blob, fee.NewECDHESUnwrapper(ecdhKID, priv), start, end)
	require.Equal(t, plaintext[start:end+1], got)
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

	for _, rg := range []struct{ start, end int64 }{
		{0, 0}, {1, rangeChunk}, {rangeChunk - 1, rangeChunk}, {2 * rangeChunk, 5*rangeChunk - 1},
		{5 * rangeChunk, 5*rangeChunk + 122}, {size - 1, size - 1},
	} {
		_, got := decryptRange(t, f.blob, f.unwrapper, rg.start, rg.end)
		require.Equal(t, full[rg.start:rg.start+int64(len(got))], got)
	}
}
