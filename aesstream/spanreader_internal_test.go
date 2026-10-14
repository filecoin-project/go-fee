package aesstream

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestChunkLayout pins the chunk-geometry math for the boundary lengths
// the public range API depends on.
func TestChunkLayout(t *testing.T) {
	const cs = MinChunkSize
	enc := int64(cs) + TagSize

	cases := []struct {
		name                                   string
		ciphertextSize                         int64
		wantChunks, wantLastLen, wantPlaintext int64
	}{
		{"empty stream (one tag-only chunk)", TagSize, 1, TagSize, 0},
		{"single partial chunk", TagSize + 100, 1, TagSize + 100, 100},
		{"single full chunk", enc, 1, enc, cs},
		{"full + partial final", enc + TagSize + 7, 2, TagSize + 7, cs + 7},
		{"two full chunks", 2 * enc, 2, enc, 2 * cs},
	}
	for _, c := range cases {
		n, last, plain, err := chunkLayout(c.ciphertextSize, cs)
		require.NoErrorf(t, err, "%s: chunkLayout(%d)", c.name, c.ciphertextSize)
		require.Equalf(t, c.wantChunks, n, "%s: numChunks", c.name)
		require.Equalf(t, c.wantLastLen, last, "%s: lastCipherLen", c.name)
		require.Equalf(t, c.wantPlaintext, plain, "%s: plaintextLen", c.name)
	}
}

// TestChunkLayoutRejectsTrailingEmptyChunk: an empty final chunk is valid only
// as the sole chunk of an empty plaintext, so a length that ends in one after
// full chunks is not a stream.
func TestChunkLayoutRejectsTrailingEmptyChunk(t *testing.T) {
	const cs = MinChunkSize
	enc := int64(cs) + TagSize
	for _, size := range []int64{enc + TagSize, 3*enc + TagSize} {
		_, _, _, err := chunkLayout(size, cs)
		require.ErrorIsf(t, err, ErrCiphertextSize, "chunkLayout(%d)", size)
	}
}

// TestReaderRejectsTrailingEmptyChunk: the streaming reader refuses the same
// layout, even when every chunk in it authenticates.
func TestReaderRejectsTrailingEmptyChunk(t *testing.T) {
	const cs = MinChunkSize
	cfg := internalConfig(cs)
	aead, err := newGCM(cfg.Key)
	require.NoError(t, err)
	var base [BaseNonceSize]byte
	copy(base[:], cfg.BaseNonce)

	plaintext := bytes.Repeat([]byte{0x42}, cs)
	first := streamNonce(base, 0, false)
	last := streamNonce(base, 1, true)
	stream := aead.Seal(nil, first[:], plaintext, cfg.AAD)
	stream = aead.Seal(stream, last[:], nil, cfg.AAD)

	r, err := NewReader(bytes.NewReader(stream), cfg)
	require.NoError(t, err)
	defer r.Close()
	_, err = io.ReadAll(r)
	require.ErrorIs(t, err, ErrCiphertextSize)
}

// TestChunkLayoutTooManyChunks verifies the MaxChunks guard, which the
// public API cannot reach without an impractically large ciphertext.
func TestChunkLayoutTooManyChunks(t *testing.T) {
	const cs = MinChunkSize
	enc := int64(cs) + TagSize
	// One chunk past the uint32 counter's capacity.
	size := (int64(MaxChunks) + 1) * enc
	_, _, _, err := chunkLayout(size, cs)
	require.ErrorIsf(t, err, ErrTooManyChunks, "chunkLayout(%d)", size)
}
