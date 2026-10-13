package aesstream_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/filecoin-project/go-fee/aesstream"
	"github.com/stretchr/testify/require"
)

// TestPooledBuffersRoundTrip runs many short streams through every pooled
// type back to back, closing each, so buffers are recycled across streams:
// a stale byte or a mis-reset slice would break a later round trip.
func TestPooledBuffersRoundTrip(t *testing.T) {
	const cs = aesstream.MinChunkSize
	cfg := baseConfig(cs)
	for i := 0; i < 64; i++ {
		plain := pattern(i*97 + 1)

		var sealed bytes.Buffer
		w, err := aesstream.NewWriter(&sealed, cfg)
		require.NoError(t, err)
		_, err = w.Write(plain)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		er, err := aesstream.NewEncryptReader(bytes.NewReader(plain), cfg)
		require.NoError(t, err)
		viaReader, err := io.ReadAll(er)
		require.NoError(t, err)
		require.NoError(t, er.Close())
		require.Equal(t, sealed.Bytes(), viaReader)

		r, err := aesstream.NewReader(bytes.NewReader(sealed.Bytes()), cfg)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		require.Equal(t, plain, got)

		sr, err := aesstream.NewSpanReader(bytes.NewReader(sealed.Bytes()), cfg, int64(sealed.Len()), 0, int64(len(plain))-1)
		require.NoError(t, err)
		got, err = io.ReadAll(sr)
		require.NoError(t, err)
		require.NoError(t, sr.Close())
		require.Equal(t, plain, got)
	}
}

// TestCloseEndsReads: after Close, Reader and SpanReader fail rather than
// serve (possibly recycled) buffer contents, and Close is idempotent.
func TestCloseEndsReads(t *testing.T) {
	const cs = aesstream.MinChunkSize
	cfg := baseConfig(cs)
	plain := pattern(3 * cs)
	ct, err := aesstream.Seal(cfg, plain)
	require.NoError(t, err)

	r, err := aesstream.NewReader(bytes.NewReader(ct), cfg)
	require.NoError(t, err)
	_, err = r.Read(make([]byte, 10))
	require.NoError(t, err)
	require.NoError(t, r.Close())
	require.NoError(t, r.Close())
	_, err = r.Read(make([]byte, 10))
	require.Error(t, err)

	sr, err := aesstream.NewSpanReader(bytes.NewReader(ct), cfg, int64(len(ct)), 0, int64(len(plain))-1)
	require.NoError(t, err)
	_, err = sr.Read(make([]byte, 10))
	require.NoError(t, err)
	require.NoError(t, sr.Close())
	require.NoError(t, sr.Close())
	_, err = sr.Read(make([]byte, 10))
	require.Error(t, err)
}

// TestClosedStreamAllocatesNothing: a stream opened after a closed one of
// the same chunk size takes its buffers from the pool.
func TestClosedStreamAllocatesNothing(t *testing.T) {
	cfg := baseConfig(0)
	plain := pattern(100)
	// Warm the pool once.
	er, err := aesstream.NewEncryptReader(bytes.NewReader(plain), cfg)
	require.NoError(t, err)
	_, _ = io.ReadAll(er)
	require.NoError(t, er.Close())

	allocs := testing.AllocsPerRun(20, func() {
		er, err := aesstream.NewEncryptReader(bytes.NewReader(plain), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, er); err != nil {
			t.Fatal(err)
		}
		er.Close()
	})
	// The reader struct, its AAD copy, the GCM AEAD and the source: small
	// allocations only, never the two chunk buffers.
	require.Less(t, allocs, 12.0, "allocs per pooled stream")
}
