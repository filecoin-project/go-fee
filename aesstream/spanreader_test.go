package aesstream_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/filecoin-project/go-fee/aesstream"
)

// seal encrypts pt under cfg, failing the test on error. (The package's own
// tests call aesstream.Seal inline; the range tests seal often enough to
// warrant a helper.)
func seal(t *testing.T, cfg aesstream.Config, pt []byte) []byte {
	t.Helper()
	ct, err := aesstream.Seal(cfg, pt)
	require.NoError(t, err, "Seal")
	return ct
}

// fetchSpan returns the contiguous ciphertext span a caller would fetch to
// serve plaintext [off, off+length) — ct[start:start+n] where (start, n) =
// CiphertextRange — as a sequential io.Reader, mirroring a single range
// request whose body is handed to SpanReader. (Setup helper for tests that
// aren't themselves checking CiphertextRange's output.)
func fetchSpan(t *testing.T, ct []byte, ciphertextSize int64, chunkSize int, off, length int64) io.Reader {
	t.Helper()
	start, n, _, err := aesstream.CiphertextRange(ciphertextSize, chunkSize, off, length)
	require.NoErrorf(t, err, "CiphertextRange off=%d len=%d", off, length)
	return bytes.NewReader(ct[start : start+n])
}

// countingReader records how many bytes were read through it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// drainTiny reads r to EOF one byte at a time, asserting a clean EOF.
func drainTiny(t *testing.T, r io.Reader) []byte {
	t.Helper()
	// Non-nil empty slice so a zero-length range compares equal (via
	// require.Equal) to the non-nil empty slice OpenSpan returns.
	out := []byte{}
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			return out
		}
		require.NoError(t, err, "Read")
	}
}

// TestSpanReader exercises range decryption from a prefetched ciphertext
// span (SpanReader / OpenSpan).
func TestSpanReader(t *testing.T) {
	const cs = aesstream.MinChunkSize    // 4096
	enc := int64(cs) + aesstream.TagSize // 4112: a full ciphertext chunk

	// Ranges is the core check, table-driven with hand-computed expectations
	// (chunk size 4096, so a full ciphertext chunk is 4112 bytes). The
	// wantStart/wantN/wantLen values are literals, not re-derived from the
	// range math, so the test is an independent oracle: it pins the exact
	// ciphertext span CiphertextRange must report, that SpanReader/OpenSpan
	// reproduce the right plaintext from exactly that span, and that the span
	// is consumed in full and no further.
	t.Run("Ranges", func(t *testing.T) {
		cases := []struct {
			name             string
			plaintextLen     int
			off, length      int64
			wantStart, wantN int64 // expected CiphertextRange output
			wantLen          int64 // expected decrypted length (clamped)
		}{
			{"empty plaintext", 0, 0, 10, 0, 0, 0},
			{"single chunk, head", 100, 0, 10, 0, 116, 10},
			{"single chunk, mid", 100, 10, 20, 0, 116, 20},
			{"single chunk, length clamps at end", 100, 90, 1000, 0, 116, 10},
			{"offset at end is an empty read", 100, 100, 5, 0, 0, 0},
			{"exactly one full chunk", 4096, 0, 4096, 0, 4112, 4096},
			{"two chunks, within the final chunk", 5000, 4100, 50, 4112, 920, 50},
			{"three chunks, spanning an interior boundary", 10000, 4090, 20, 0, 8224, 20},
			{"three chunks, within the middle chunk", 10000, 5000, 100, 4112, 4112, 100},
			{"three chunks, final partial chunk, clamped", 10000, 9000, 2000, 8224, 1824, 1000},
			{"whole multi-chunk object", 10000, 0, 10000, 0, 10048, 10000},
		}
		cfg := baseConfig(cs)
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pt := pattern(tc.plaintextLen)
				ct := seal(t, cfg, pt)
				size := int64(len(ct))
				want := pt[tc.off : tc.off+tc.wantLen]

				// CiphertextRange reports exactly the expected span, and the
				// clamped plaintext length of the range.
				start, n, plainLen, err := aesstream.CiphertextRange(size, cs, tc.off, tc.length)
				require.NoError(t, err, "CiphertextRange")
				require.Equal(t, tc.wantStart, start, "start")
				require.Equal(t, tc.wantN, n, "n")
				require.Equal(t, tc.wantLen, plainLen, "plainLen")

				// Decrypt from a reader over exactly that span — sliced by the
				// literal bounds, so this does not lean on CiphertextRange —
				// and confirm the whole span is consumed and no more.
				cr := &countingReader{r: bytes.NewReader(ct[tc.wantStart : tc.wantStart+tc.wantN])}
				got, err := aesstream.OpenSpan(cfg, cr, size, tc.off, tc.length)
				require.NoError(t, err, "OpenSpan")
				require.Equal(t, want, got, "OpenSpan output")
				require.Equal(t, tc.wantN, cr.n, "should consume exactly the span")

				// The streaming reader, drained one byte at a time, agrees —
				// and its Len matches CiphertextRange's plainLen, tying the
				// clamping rule to a single place.
				rr, err := aesstream.NewSpanReader(bytes.NewReader(ct[tc.wantStart:tc.wantStart+tc.wantN]), cfg, size, tc.off, tc.length)
				require.NoError(t, err, "NewSpanReader")
				require.Equal(t, tc.wantLen, rr.Len(), "Len")
				require.Equal(t, plainLen, rr.Len(), "Len agrees with CiphertextRange plainLen")
				require.Equal(t, want, drainTiny(t, rr), "streamed output")
			})
		}
	})

	// RoundTrip reads each sealed object back in full through a sequence of
	// adjacent range reads of various widths (chunk-aligned and not) and
	// confirms the reassembly equals the original plaintext — an end-to-end
	// encrypt → range-read → reassemble check whose oracle is the plaintext
	// itself, not the range math. A consumer learns where to stop from
	// DecryptedSize, so the test does too.
	t.Run("RoundTrip", func(t *testing.T) {
		cfg := baseConfig(cs)
		sizes := []int{0, 1, cs - 1, cs, cs + 1, 2*cs + 1, 5*cs + 777}
		windows := []int64{100, 1000, cs, cs + 1, 7777, 3 * cs}
		for _, plen := range sizes {
			pt := pattern(plen)
			ct := seal(t, cfg, pt)
			size := int64(len(ct))

			// The plaintext length is recovered from the ciphertext length.
			plaintextLen, err := aesstream.DecryptedSize(size, cs)
			require.NoErrorf(t, err, "DecryptedSize plen=%d", plen)
			require.Equalf(t, int64(plen), plaintextLen, "DecryptedSize plen=%d", plen)

			for _, w := range windows {
				oneShot, streamed := []byte{}, []byte{}
				for off := int64(0); off < plaintextLen; off += w {
					got, err := aesstream.OpenSpan(cfg, fetchSpan(t, ct, size, cs, off, w), size, off, w)
					require.NoErrorf(t, err, "OpenSpan plen=%d w=%d off=%d", plen, w, off)
					oneShot = append(oneShot, got...)

					rr, err := aesstream.NewSpanReader(fetchSpan(t, ct, size, cs, off, w), cfg, size, off, w)
					require.NoErrorf(t, err, "NewSpanReader plen=%d w=%d off=%d", plen, w, off)
					data, err := io.ReadAll(rr)
					require.NoErrorf(t, err, "ReadAll plen=%d w=%d off=%d", plen, w, off)
					streamed = append(streamed, data...)
				}
				require.Equalf(t, pt, oneShot, "one-shot reassembly plen=%d w=%d", plen, w)
				require.Equalf(t, pt, streamed, "streamed reassembly plen=%d w=%d", plen, w)
			}
		}
	})

	// Tampered checks that a range over a tampered chunk errors rather than
	// returning corrupt plaintext — and that a range not overlapping the
	// tampered chunk is unaffected, since that chunk is never in the span.
	t.Run("Tampered", func(t *testing.T) {
		cfg := baseConfig(cs)
		pt := pattern(3*cs + 123) // chunks 0,1,2 full + chunk 3 partial
		tampered := seal(t, cfg, pt)
		tampered[enc+100] ^= 0x01 // flip a bit inside chunk 1
		size := int64(len(tampered))

		t.Run("range over tampered chunk errors", func(t *testing.T) {
			// The span for a range inside chunk 1 is exactly chunk 1.
			span := bytes.NewReader(tampered[enc : 2*enc])
			_, err := aesstream.OpenSpan(cfg, span, size, cs+10, 20)
			require.ErrorIs(t, err, aesstream.ErrCorrupted)
		})

		t.Run("range not overlapping tampered chunk is unaffected", func(t *testing.T) {
			// The span for [0,100] is chunk 0 only; chunk 1 is never fetched.
			span := bytes.NewReader(tampered[0:enc])
			got, err := aesstream.OpenSpan(cfg, span, size, 0, 100)
			require.NoError(t, err)
			require.Equal(t, pt[:100], got)
		})
	})

	// ShortSpan: a span shorter than the geometry requires is reported as
	// ErrShortSpan (an under-fetch — a retryable fetch-side problem) rather
	// than yielding partial plaintext, and is distinguishable from
	// ErrTruncated (a stored stream that was itself cut short).
	t.Run("ShortSpan", func(t *testing.T) {
		cfg := baseConfig(cs)
		ct := seal(t, cfg, pattern(2*cs))
		size := int64(len(ct))
		start, n, _, err := aesstream.CiphertextRange(size, cs, 0, 2*cs)
		require.NoError(t, err)
		short := ct[start : start+n-1] // one byte short of the needed span
		_, err = aesstream.OpenSpan(cfg, bytes.NewReader(short), size, 0, 2*cs)
		require.ErrorIs(t, err, aesstream.ErrShortSpan)
		require.NotErrorIs(t, err, aesstream.ErrTruncated, "a short span is not stream truncation")
	})

	// WrongCiphertextSize shows the declared total length pins the
	// final-chunk flag: lie about the size so the true (final) chunk looks
	// like a non-final one, and authentication fails rather than silently
	// returning data sealed under a different nonce.
	t.Run("WrongCiphertextSize", func(t *testing.T) {
		cfg := baseConfig(cs)
		ct := seal(t, cfg, pattern(cs)) // exactly one full, final chunk

		// Claim two chunks: chunk 0 is now treated as non-final (flag 0x00),
		// but it was sealed as the final chunk (flag 0x01).
		_, err := aesstream.OpenSpan(cfg, bytes.NewReader(ct), 2*enc, 0, cs)
		require.ErrorIs(t, err, aesstream.ErrCorrupted)
	})

	// OutOfRange covers offset/length validation: negative inputs and an
	// offset past the end are ErrRange; an offset exactly at the end is a
	// valid empty read; a length past the end clamps.
	t.Run("OutOfRange", func(t *testing.T) {
		cfg := baseConfig(cs)
		const n = 2*cs + 50
		ct := seal(t, cfg, pattern(n))
		size := int64(len(ct))

		bad := []struct {
			name        string
			off, length int64
		}{
			{"negative off", -1, 10},
			{"negative length", 0, -1},
			{"off past end", int64(n) + 1, 0},
		}
		for _, c := range bad {
			_, err := aesstream.NewSpanReader(bytes.NewReader(nil), cfg, size, c.off, c.length)
			require.ErrorIsf(t, err, aesstream.ErrRange, "%s", c.name)
		}

		// Offset exactly at the end: a valid zero-length read that consumes
		// no ciphertext.
		got, err := aesstream.OpenSpan(cfg, bytes.NewReader(nil), size, int64(n), 100)
		require.NoError(t, err, "OpenSpan at end")
		require.Empty(t, got, "OpenSpan at end yields no bytes")

		// Length past the end clamps to the available bytes.
		got, err = aesstream.OpenSpan(cfg, fetchSpan(t, ct, size, cs, int64(n)-10, 1000), size, int64(n)-10, 1000)
		require.NoError(t, err, "OpenSpan clamping")
		require.Len(t, got, 10, "length past end clamps to available bytes")
	})

	// EmptyPlaintext checks the empty-stream corner: the only valid offset is
	// 0, which yields no bytes; any positive offset is ErrRange.
	t.Run("EmptyPlaintext", func(t *testing.T) {
		cfg := baseConfig(cs)
		ct := seal(t, cfg, nil) // one empty final chunk (TagSize bytes)
		size := int64(len(ct))

		got, err := aesstream.OpenSpan(cfg, bytes.NewReader(nil), size, 0, 10)
		require.NoError(t, err, "OpenSpan(empty, off=0)")
		require.Empty(t, got, "empty plaintext yields no bytes")

		_, err = aesstream.NewSpanReader(bytes.NewReader(nil), cfg, size, 1, 0)
		require.ErrorIs(t, err, aesstream.ErrRange, "OpenSpan(empty, off=1)")
	})

	// InvalidCiphertextSize rejects declared lengths that cannot be a stream
	// this package produced.
	t.Run("InvalidCiphertextSize", func(t *testing.T) {
		cfg := baseConfig(cs)

		for _, size := range []int64{0, 1, aesstream.TagSize - 1, enc + 5} {
			_, err := aesstream.NewSpanReader(bytes.NewReader(nil), cfg, size, 0, 1)
			require.ErrorIsf(t, err, aesstream.ErrCiphertextSize, "NewSpanReader(size=%d)", size)

			_, err = aesstream.DecryptedSize(size, cs)
			require.ErrorIsf(t, err, aesstream.ErrCiphertextSize, "DecryptedSize(%d)", size)
		}
	})

	// BadConfig confirms cfg validation runs before any range math.
	t.Run("BadConfig", func(t *testing.T) {
		cfg := baseConfig(cs)
		cfg.Key = cfg.Key[:16] // wrong length
		_, err := aesstream.NewSpanReader(bytes.NewReader(nil), cfg, 64, 0, 1)
		require.ErrorIs(t, err, aesstream.ErrKeySize)
	})

	// DefaultChunkSize exercises the default 256 KiB chunk path, including a
	// boundary-spanning range, to confirm the geometry is not hard-coded to
	// the test's small chunk size.
	t.Run("DefaultChunkSize", func(t *testing.T) {
		cfg := baseConfig(0) // default 256 KiB
		const dc = aesstream.DefaultChunkSize
		pt := pattern(2*dc + 1000)
		ct := seal(t, cfg, pt)
		size := int64(len(ct))

		for _, c := range []struct{ off, length int64 }{
			{0, 100},
			{dc - 50, 100}, // spans the first boundary
			{2 * dc, 1000}, // the partial final chunk
			{dc + 12345, 60000},
		} {
			got, err := aesstream.OpenSpan(cfg, fetchSpan(t, ct, size, dc, c.off, c.length), size, c.off, c.length)
			require.NoErrorf(t, err, "off=%d len=%d", c.off, c.length)
			require.Equalf(t, pt[c.off:c.off+c.length], got, "off=%d len=%d", c.off, c.length)
		}
	})

	// StickyError: once a Read has failed, every later Read must repeat the
	// same error and yield no bytes — the property the "plaintext is
	// incomplete and must be discarded" contract rests on.
	t.Run("StickyError", func(t *testing.T) {
		cfg := baseConfig(cs)
		pt := pattern(2 * cs)
		ct := seal(t, cfg, pt)
		size := int64(len(ct))

		assertSticky := func(t *testing.T, r *aesstream.SpanReader, want error) {
			t.Helper()
			buf := make([]byte, cs)
			var firstErr error
			for firstErr == nil {
				_, firstErr = r.Read(buf)
			}
			require.ErrorIs(t, firstErr, want, "first error")
			for range 3 {
				n, err := r.Read(buf)
				require.Zero(t, n, "no bytes after a terminal error")
				require.ErrorIs(t, err, want, "the error must repeat, not resume")
			}
		}

		t.Run("Corrupted", func(t *testing.T) {
			tampered := append([]byte(nil), ct...)
			tampered[enc+10] ^= 0x01 // inside chunk 1
			r, err := aesstream.NewSpanReader(bytes.NewReader(tampered), cfg, size, 0, int64(2*cs))
			require.NoError(t, err)
			assertSticky(t, r, aesstream.ErrCorrupted)
		})

		t.Run("ShortSpan", func(t *testing.T) {
			r, err := aesstream.NewSpanReader(bytes.NewReader(ct[:len(ct)-1]), cfg, size, 0, int64(2*cs))
			require.NoError(t, err)
			assertSticky(t, r, aesstream.ErrShortSpan)
		})
	})

	// OverlongSpan: real servers over-serve range requests, so bytes past the
	// chunks the range needs are ignored and never read — a deliberate
	// divergence from the whole-stream Reader's ErrTrailingData.
	t.Run("OverlongSpan", func(t *testing.T) {
		cfg := baseConfig(cs)
		pt := pattern(3 * cs)
		ct := seal(t, cfg, pt)
		size := int64(len(ct))

		// A range within chunk 0, handed the whole stream plus garbage.
		over := append(append([]byte(nil), ct...), 0xAA, 0xBB, 0xCC)
		cr := &countingReader{r: bytes.NewReader(over)}
		got, err := aesstream.OpenSpan(cfg, cr, size, 10, 100)
		require.NoError(t, err, "an over-long span must be tolerated")
		require.Equal(t, pt[10:110], got)
		require.Equal(t, enc, cr.n, "only the chunks the range needs are read")
	})

	// AADMismatch: a range read under an AAD that doesn't match the sealed
	// stream fails authentication (the key and nonce are correct, so this
	// isolates the AAD binding on the span path).
	t.Run("AADMismatch", func(t *testing.T) {
		cfg := baseConfig(cs)
		ct := seal(t, cfg, pattern(cs+100))
		size := int64(len(ct))

		bad := cfg
		bad.AAD = []byte("a different enc-structure")
		_, err := aesstream.OpenSpan(bad, fetchSpan(t, ct, size, cs, 0, 50), size, 0, 50)
		require.ErrorIs(t, err, aesstream.ErrCorrupted)
	})

	// AADAliasing: NewSpanReader copies cfg.AAD, so mutating the caller's
	// slice after construction must not change what the reader authenticates.
	t.Run("AADAliasing", func(t *testing.T) {
		cfg := baseConfig(cs)
		pt := pattern(cs + 100)
		ct := seal(t, cfg, pt)
		size := int64(len(ct))

		r, err := aesstream.NewSpanReader(fetchSpan(t, ct, size, cs, 0, 100), cfg, size, 0, 100)
		require.NoError(t, err)
		cfg.AAD[0] ^= 0xFF
		got, err := io.ReadAll(r)
		require.NoError(t, err, "mutating the caller's AAD after construction must not affect the reader")
		require.Equal(t, pt[:100], got)
	})

	// SourceError: a span source that dies with a non-EOF error (errReader,
	// standing in for a transport failure mid-fetch) surfaces that error
	// wrapped with the chunk index, not misclassified as a short span.
	t.Run("SourceError", func(t *testing.T) {
		cfg := baseConfig(cs)
		ct := seal(t, cfg, pattern(cs))
		size := int64(len(ct))

		r, err := aesstream.NewSpanReader(&errReader{}, cfg, size, 0, 10)
		require.NoError(t, err)
		_, err = io.ReadAll(r)
		require.ErrorIs(t, err, errReadBoom, "the transport error must surface, wrapped")
		require.NotErrorIs(t, err, aesstream.ErrShortSpan)
		require.ErrorContains(t, err, "chunk 0")
	})

	// ZeroLengthRange: Len and ChunkSize are well-defined on an empty range,
	// no ciphertext is read, and Read reports EOF immediately.
	t.Run("ZeroLengthRange", func(t *testing.T) {
		cfg := baseConfig(cs)
		ct := seal(t, cfg, pattern(100))
		size := int64(len(ct))

		cr := &countingReader{r: bytes.NewReader(nil)}
		r, err := aesstream.NewSpanReader(cr, cfg, size, 5, 0)
		require.NoError(t, err)
		require.Zero(t, r.Len(), "Len")
		require.Equal(t, cs, r.ChunkSize(), "ChunkSize")
		n, err := r.Read(make([]byte, 8))
		require.Zero(t, n)
		require.ErrorIs(t, err, io.EOF)
		require.Zero(t, cr.n, "no ciphertext read for an empty range")
	})
}

// TestCiphertextRange covers CiphertextRange's input validation. Its
// span-geometry output is pinned by the literal table in TestSpanReader/Ranges.
func TestCiphertextRange(t *testing.T) {
	const cs = aesstream.MinChunkSize
	ct := seal(t, baseConfig(cs), pattern(2*cs))
	size := int64(len(ct))

	_, _, _, err := aesstream.CiphertextRange(size, cs, -1, 10)
	require.ErrorIs(t, err, aesstream.ErrRange, "negative off")
	_, _, _, err = aesstream.CiphertextRange(size, cs, 0, -1)
	require.ErrorIs(t, err, aesstream.ErrRange, "negative length")
	_, _, _, err = aesstream.CiphertextRange(size, cs, size, 1) // past plaintext end
	require.ErrorIs(t, err, aesstream.ErrRange, "off past end")
	_, _, _, err = aesstream.CiphertextRange(aesstream.TagSize-1, cs, 0, 1)
	require.ErrorIs(t, err, aesstream.ErrCiphertextSize, "invalid ciphertext size")
}

// TestGeometryChunkSizeValidation checks that the bare-chunkSize geometry
// helpers agree with Config.validate: zero selects the default, anything
// else outside [MinChunkSize, MaxChunkSize] is ErrChunkSize rather than a
// plausible wrong geometry. (DecryptedSize feeds Content-Length decisions
// without any ciphertext in hand, so a silent mis-plumbed chunk size there
// surfaces late — as ErrCorrupted mid-stream — or not at all.)
func TestGeometryChunkSizeValidation(t *testing.T) {
	const cs = aesstream.MinChunkSize
	ct := seal(t, baseConfig(cs), pattern(10000))
	size := int64(len(ct))

	for _, bad := range []int{-1, 1, 7, 512, aesstream.MinChunkSize - 1, aesstream.MaxChunkSize + 1} {
		_, err := aesstream.DecryptedSize(size, bad)
		require.ErrorIsf(t, err, aesstream.ErrChunkSize, "DecryptedSize(chunkSize=%d)", bad)
		_, _, _, err = aesstream.CiphertextRange(size, bad, 0, 10)
		require.ErrorIsf(t, err, aesstream.ErrChunkSize, "CiphertextRange(chunkSize=%d)", bad)
	}

	// Zero still selects DefaultChunkSize in both helpers.
	dct := seal(t, baseConfig(0), pattern(100))
	n, err := aesstream.DecryptedSize(int64(len(dct)), 0)
	require.NoError(t, err, "DecryptedSize(chunkSize=0)")
	require.Equal(t, int64(100), n, "DecryptedSize at the default chunk size")
	_, _, plainLen, err := aesstream.CiphertextRange(int64(len(dct)), 0, 10, 20)
	require.NoError(t, err, "CiphertextRange(chunkSize=0)")
	require.Equal(t, int64(20), plainLen, "CiphertextRange at the default chunk size")
}

// TestDecryptedSize_InvertsEncryptedSize checks the geometry helpers agree:
// DecryptedSize undoes EncryptedSize for every plaintext length.
func TestDecryptedSize_InvertsEncryptedSize(t *testing.T) {
	const cs = aesstream.MinChunkSize
	for _, n := range []int64{0, 1, 15, cs - 1, cs, cs + 1, 2 * cs, 2*cs + 1, 3*cs + 123} {
		ctLen := aesstream.EncryptedSize(n, cs)
		got, err := aesstream.DecryptedSize(ctLen, cs)
		require.NoErrorf(t, err, "DecryptedSize(%d)", ctLen)
		require.Equalf(t, n, got, "DecryptedSize(EncryptedSize(%d))", n)
	}
}

// TestChunkCount pins the exported chunk count over the boundary ciphertext
// lengths, including the two encodings of an exact-multiple plaintext: the same
// plaintext length is one chunk more when the stream ends with an empty final
// chunk, which is why callers must not re-derive the count from a plaintext size.
func TestChunkCount(t *testing.T) {
	const cs = aesstream.MinChunkSize
	enc := int64(cs) + aesstream.TagSize

	cases := map[string]struct {
		ciphertextLen int64
		want          int64
	}{
		"empty stream (one tag-only chunk)": {aesstream.TagSize, 1},
		"single partial chunk":              {aesstream.TagSize + 100, 1},
		"single full chunk":                 {enc, 1},
		"full + empty final":                {enc + aesstream.TagSize, 2},
		"full + partial final":              {enc + aesstream.TagSize + 7, 2},
		"two full chunks":                   {2 * enc, 2},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := aesstream.ChunkCount(c.ciphertextLen, cs)
			require.NoError(t, err)
			require.Equal(t, c.want, got)
		})
	}
}

// TestChunkCountInvalid confirms ChunkCount reports the same errors as the rest
// of the geometry API for a length or chunk size that cannot describe a stream.
func TestChunkCountInvalid(t *testing.T) {
	t.Run("ciphertext too short to hold a tag", func(t *testing.T) {
		_, err := aesstream.ChunkCount(aesstream.TagSize-1, aesstream.MinChunkSize)
		require.ErrorIs(t, err, aesstream.ErrCiphertextSize)
	})

	t.Run("chunk size out of range", func(t *testing.T) {
		_, err := aesstream.ChunkCount(aesstream.TagSize, aesstream.MinChunkSize-1)
		require.ErrorIs(t, err, aesstream.ErrChunkSize)
	})

	t.Run("zero chunk size selects the default", func(t *testing.T) {
		got, err := aesstream.ChunkCount(aesstream.EncryptedSize(3*aesstream.DefaultChunkSize, 0), 0)
		require.NoError(t, err)
		require.Equal(t, int64(3), got)
	})
}
