package aesstream_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/filecoin-project/go-fee/aesstream"
	"github.com/stretchr/testify/require"
)

// TestEncryptReaderMatchesWriter pins the pull-mode encryptor to Writer's
// output byte for byte, around every chunk boundary that matters, for
// sources that deliver the plaintext in one read and in one-byte reads.
func TestEncryptReaderMatchesWriter(t *testing.T) {
	const cs = aesstream.MinChunkSize
	cfg := baseConfig(cs)
	for _, n := range []int{0, 1, cs - 1, cs, cs + 1, 2 * cs, 2*cs + 1, 5*cs + 17} {
		plain := pattern(n)
		want, err := aesstream.Seal(cfg, plain)
		require.NoError(t, err)

		for name, src := range map[string]io.Reader{
			"one read": bytes.NewReader(plain),
			"one byte": iotest.OneByteReader(bytes.NewReader(plain)),
			"half":     iotest.HalfReader(bytes.NewReader(plain)),
			"data-err": iotest.DataErrReader(bytes.NewReader(plain)),
		} {
			r, err := aesstream.NewEncryptReader(src, cfg)
			require.NoError(t, err)
			got, err := io.ReadAll(iotest.OneByteReader(r))
			require.NoError(t, err, "%d bytes, %s", n, name)
			require.Equal(t, want, got, "%d bytes, %s", n, name)
		}

		// WriteTo delivers the same bytes, one sealed chunk per write.
		r, err := aesstream.NewEncryptReader(bytes.NewReader(plain), cfg)
		require.NoError(t, err)
		var sink chunkSink
		written, err := r.WriteTo(&sink)
		require.NoError(t, err)
		require.Equal(t, int64(len(want)), written)
		require.Equal(t, want, sink.buf.Bytes())
		wantChunks := (n + cs - 1) / cs
		if wantChunks == 0 {
			wantChunks = 1
		}
		require.Equal(t, wantChunks, sink.writes, "%d bytes: one write per chunk", n)
		for _, w := range sink.sizes[:len(sink.sizes)-1] {
			require.Equal(t, cs+aesstream.TagSize, w)
		}
	}
}

// chunkSink records every write it receives.
type chunkSink struct {
	buf    bytes.Buffer
	writes int
	sizes  []int
}

func (s *chunkSink) Write(p []byte) (int, error) {
	s.writes++
	s.sizes = append(s.sizes, len(p))
	return s.buf.Write(p)
}

// TestEncryptReaderSourceError ends the stream before its final chunk: what
// was produced is a truncated ciphertext, never a complete one.
func TestEncryptReaderSourceError(t *testing.T) {
	const cs = aesstream.MinChunkSize
	cfg := baseConfig(cs)
	plain := pattern(3*cs + 5)
	boom := errors.New("boom")
	src := io.MultiReader(bytes.NewReader(plain), iotest.ErrReader(boom))

	r, err := aesstream.NewEncryptReader(src, cfg)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.ErrorIs(t, err, boom)
	// Three full chunks were sealed before the error; the short final one
	// was not.
	require.Equal(t, 3*(cs+aesstream.TagSize), len(got))
	_, err = aesstream.Open(cfg, got)
	require.ErrorIs(t, err, aesstream.ErrTruncated)

	// The error is sticky.
	_, err = r.Read(make([]byte, 1))
	require.ErrorIs(t, err, boom)
}

// TestEncryptReaderClose: reads after Close fail rather than continue the
// stream, and Close is idempotent.
func TestEncryptReaderClose(t *testing.T) {
	cfg := baseConfig(aesstream.MinChunkSize)
	r, err := aesstream.NewEncryptReader(bytes.NewReader(pattern(3*aesstream.MinChunkSize)), cfg)
	require.NoError(t, err)
	_, err = r.Read(make([]byte, 16))
	require.NoError(t, err)
	require.NoError(t, r.Close())
	require.NoError(t, r.Close())
	_, err = io.ReadAll(r)
	require.Error(t, err)
}

// TestEncryptReaderWriteToDestinationError surfaces the destination's error
// and reports the bytes written before it.
func TestEncryptReaderWriteToDestinationError(t *testing.T) {
	const cs = aesstream.MinChunkSize
	cfg := baseConfig(cs)
	r, err := aesstream.NewEncryptReader(bytes.NewReader(pattern(3*cs)), cfg)
	require.NoError(t, err)
	boom := errors.New("full")
	n, err := r.WriteTo(&failAfter{limit: 1, err: boom})
	require.ErrorIs(t, err, boom)
	require.Equal(t, int64(0), n)
	_, err = r.Read(make([]byte, 1))
	require.ErrorIs(t, err, boom)
}

// failAfter accepts limit-1 writes then fails.
type failAfter struct {
	limit, seen int
	err         error
}

func (f *failAfter) Write(p []byte) (int, error) {
	f.seen++
	if f.seen >= f.limit {
		return 0, f.err
	}
	return len(p), nil
}
