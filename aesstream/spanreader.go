package aesstream

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math"
)

// Range-decryption errors, in addition to the decryption sentinels in
// aesstream.go.
var (
	// ErrCiphertextSize is returned when a declared ciphertext length cannot
	// be a structurally valid stream: it is shorter than a single (empty)
	// chunk, or its trailing chunk is too short to hold an authentication
	// tag. It is a structural complaint about the length the caller supplied,
	// distinct from ErrCorrupted (a chunk that failed authentication).
	ErrCiphertextSize = fmt.Errorf("aesstream: ciphertext length is not a valid stream (the final chunk must be at least %d bytes, to hold the tag)", TagSize)

	// ErrRange is returned when a requested plaintext range is unsatisfiable:
	// a negative start, an end before the start, or a start past the last
	// plaintext byte — HTTP Range semantics, where there is no such thing as
	// an empty range. An end past the last byte is not an error; it is
	// clamped, exactly as HTTP clamps "bytes=a-b" to the resource length.
	ErrRange = fmt.Errorf("aesstream: requested range is out of bounds")

	// ErrShortSpan is returned when the supplied ciphertext span ends before
	// the chunks the requested range needs: the caller fetched too few bytes,
	// or the wrong span (e.g. a range response that came back short). It is a
	// fetch-side problem — the caller may re-fetch and retry — distinct from
	// ErrTruncated, which means the stored stream itself was cut short.
	ErrShortSpan = errors.New("aesstream: ciphertext span is shorter than the requested range requires")
)

// resolveChunkSize applies the DefaultChunkSize default and rejects an
// explicit chunk size outside the spec range — the same rule as
// Config.validate, for the helpers that take a bare chunkSize rather than
// a Config. Without this check a mis-plumbed chunk size would yield a
// plausible wrong geometry with no error.
func resolveChunkSize(chunkSize int) (int, error) {
	if chunkSize == 0 {
		return DefaultChunkSize, nil
	}
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize {
		return 0, ErrChunkSize
	}
	return chunkSize, nil
}

// chunkLayout derives a stream's chunk geometry from its total ciphertext
// length. Each ciphertext chunk is chunkSize+TagSize bytes except the
// final one, which holds the remainder (TagSize..chunkSize+TagSize bytes;
// exactly TagSize for an empty-plaintext stream). It returns the chunk
// count, the byte length of the final chunk, and the total plaintext
// length, or ErrCiphertextSize if ciphertextSize is not a structurally
// valid stream length, or ErrTooManyChunks if it implies more than
// MaxChunks chunks.
func chunkLayout(ciphertextSize int64, chunkSize int) (numChunks, lastCipherLen, plaintextLen int64, err error) {
	enc := int64(chunkSize) + TagSize // a full ciphertext chunk
	if ciphertextSize < TagSize {
		// Even an empty plaintext seals to one TagSize-byte chunk, so any
		// shorter length cannot be a stream this package produced.
		return 0, 0, 0, ErrCiphertextSize
	}

	q, r := ciphertextSize/enc, ciphertextSize%enc
	switch {
	case r == 0:
		// The length is an exact multiple of a full chunk: the final chunk
		// is itself full-size (its plaintext is exactly chunkSize).
		numChunks, lastCipherLen = q, enc
	case r < TagSize:
		// A trailing fragment too short to even hold a tag: malformed.
		return 0, 0, 0, ErrCiphertextSize
	default:
		// A partial (1..chunkSize-byte plaintext) or empty (TagSize-byte)
		// final chunk follows q full chunks.
		numChunks, lastCipherLen = q+1, r
	}

	if numChunks > MaxChunks {
		return 0, 0, 0, ErrTooManyChunks
	}
	plaintextLen = (numChunks-1)*int64(chunkSize) + (lastCipherLen - TagSize)
	return numChunks, lastCipherLen, plaintextLen, nil
}

// DecryptedSize returns the plaintext length, in bytes, of a stream whose
// complete ciphertext is ciphertextLen bytes long at the given chunk size.
// A zero chunkSize selects DefaultChunkSize; any other value must be in
// [MinChunkSize, MaxChunkSize] (else ErrChunkSize), the same rule as
// Config.ChunkSize. It is the inverse of EncryptedSize and returns
// ErrCiphertextSize if ciphertextLen is not a structurally valid stream
// length. Callers can use it to derive an object's plaintext size (and to
// validate a range) without fetching any ciphertext.
func DecryptedSize(ciphertextLen int64, chunkSize int) (int64, error) {
	chunkSize, err := resolveChunkSize(chunkSize)
	if err != nil {
		return 0, err
	}
	_, _, plaintextLen, err := chunkLayout(ciphertextLen, chunkSize)
	return plaintextLen, err
}

// ChunkCount returns how many chunks a complete ciphertext of ciphertextLen
// bytes contains at the given chunk size. A zero chunkSize selects
// DefaultChunkSize; any other value must be in [MinChunkSize, MaxChunkSize]
// (else ErrChunkSize), the same rule as Config.ChunkSize. It returns
// ErrCiphertextSize if ciphertextLen is not a structurally valid stream length.
//
// The count is not derivable from the plaintext length, which is why this is
// worth asking for: the final chunk may be full, partial, or empty, so a
// plaintext of exactly k*chunkSize bytes is a valid stream of either k chunks
// (the last one full) or k+1 (the last one empty). Both are read the same way
// and yield the same plaintext, and only the ciphertext length tells them apart.
// A caller checking a stream against a separately recorded chunk count should
// compare against this rather than against ceil(plaintextLen/chunkSize), which
// only describes the first form.
func ChunkCount(ciphertextLen int64, chunkSize int) (int64, error) {
	chunkSize, err := resolveChunkSize(chunkSize)
	if err != nil {
		return 0, err
	}
	numChunks, _, _, err := chunkLayout(ciphertextLen, chunkSize)
	return numChunks, err
}

// CiphertextRange returns the single contiguous ciphertext byte range
// [ctStart, ctEnd] (inclusive) that must be read to serve the plaintext
// range [start, end] (inclusive) of a stream whose complete ciphertext is
// ciphertextSize bytes long, along with plainLen, the plaintext length of
// the range after clamping. A zero chunkSize selects DefaultChunkSize; any
// other value must be in [MinChunkSize, MaxChunkSize] (else ErrChunkSize),
// the same rule as Config.ChunkSize.
//
// start/end follow HTTP Range semantics (see ErrRange): both inclusive, end
// clamped to the last plaintext byte, no empty ranges.
//
// Because the chunks overlapping any plaintext range are adjacent in the
// ciphertext, the bytes needed are always one contiguous span — so a caller
// fetching from a remote store (e.g. a range request to a blob) can pull
// them in a single request and hand the result, in order, to OpenSpan /
// NewSpanReader. The returned offsets are relative to the ciphertext stream
// itself (its first byte is 0); a caller whose blob prefixes the stream
// with an envelope header must add that header length.
//
// plainLen is the byte count the span decrypts to after end is clamped
// (SpanReader.Len, the length of OpenSpan's result). It is available before
// any ciphertext is fetched, so an HTTP consumer can size its response
// (Content-Length, the end of a Content-Range) from it rather than
// re-deriving the clamping rule.
//
// For a random-access source already in hand (a local file or in-memory
// buffer) rather than a one-shot fetch, wrap it as the span with
// io.NewSectionReader(src, ctStart, ctEnd-ctStart+1) and pass that to
// NewSpanReader.
//
// The span is chunk-aligned, so it may include a little more than the
// requested bytes: at most the unused head of the first overlapping chunk
// and tail of the last (under 2*chunkSize total), since GCM authenticates a
// whole chunk at a time. start/end and ciphertextSize are validated exactly
// as in NewSpanReader, returning ErrRange, ErrCiphertextSize or ErrChunkSize.
func CiphertextRange(ciphertextSize int64, chunkSize int, start, end int64) (ctStart, ctEnd, plainLen int64, err error) {
	chunkSize, err = resolveChunkSize(chunkSize)
	if err != nil {
		return 0, 0, 0, err
	}
	numChunks, _, plaintextLen, err := chunkLayout(ciphertextSize, chunkSize)
	if err != nil {
		return 0, 0, 0, err
	}
	if start < 0 || end < start || start > plaintextLen-1 {
		return 0, 0, 0, ErrRange
	}
	if end > plaintextLen-1 {
		end = plaintextLen - 1
	}

	enc := int64(chunkSize) + TagSize
	firstChunk := start / int64(chunkSize)
	lastChunk := end / int64(chunkSize)
	ctStart = firstChunk * enc
	ctEnd = (lastChunk+1)*enc - 1
	if lastChunk == numChunks-1 {
		// The final chunk may be short; clamp to the true stream end.
		ctEnd = ciphertextSize - 1
	}
	return ctStart, ctEnd, end - start + 1, nil
}

// SpanReader decrypts an arbitrary plaintext byte range of a chunked
// AES-256-GCM STREAM from a single contiguous slice of its ciphertext,
// delivered as a sequential io.Reader. It is the streaming counterpart to a
// remote range read: the caller computes the ciphertext span with
// CiphertextRange, fetches exactly that span in one request, and hands the
// response body here — SpanReader decrypts it into the requested plaintext
// with O(chunkSize) memory.
//
// The span must begin at the offset CiphertextRange reported (the boundary
// of the first overlapping chunk) and contain the whole chunks overlapping
// the range, in order. SpanReader recomputes that geometry from the same
// (ciphertextSize, start, end) and reads exactly the chunks it needs, so:
//
//   - the total ciphertext length pins each chunk's index, final-chunk flag
//     and length up front — no last-chunk look-ahead or retry, unlike the
//     whole-stream Reader; and
//   - the head of the first chunk (before start) and the tail of the last
//     (after end) are trimmed, so the output is exactly the range.
//
// A SpanReader implements io.Reader. Any non-EOF error means the plaintext
// is incomplete and must be discarded: a tampered/reordered/misframed chunk
// yields ErrCorrupted, and a span shorter than the geometry requires yields
// ErrShortSpan (a fetch-side problem, retryable — not ErrTruncated, which
// is reserved for a stored stream that was itself cut short). A clean
// io.EOF means the whole requested range was emitted.
//
// Unlike the whole-stream Reader, a range read cannot detect a truncated
// object: ciphertextSize is trusted. Every chunk in the span is
// authenticated, but if the declared size is smaller than the real stream,
// a range within the declared prefix decrypts cleanly — genuine plaintext
// of a silently truncated view of the object. Whole-object integrity must
// come from the layer that supplied ciphertextSize (the envelope, a CID or
// a signed manifest), not from range reads.
//
// A SpanReader is not safe for concurrent use.
type SpanReader struct {
	aead      cipher.AEAD
	src       io.Reader
	base      [BaseNonceSize]byte
	aad       []byte
	chunkSize int

	encChunk      int64 // chunkSize + TagSize: a full ciphertext chunk
	numChunks     int64 // total chunks in the stream
	lastCipherLen int64 // byte length of the final ciphertext chunk

	total     int64 // total plaintext bytes this reader will emit
	remaining int64 // plaintext bytes not yet decrypted into unread
	nextChunk int64 // index of the next chunk to read from the span
	skipFirst int   // bytes to drop from the front of the first chunk
	onFirst   bool  // nextChunk is still the first chunk of the range

	inBuf  []byte          // raw ciphertext of the current chunk, cap encChunk
	outBuf []byte          // plaintext backing array, cap chunkSize
	unread []byte          // decrypted-but-unread plaintext, trimmed to the range
	nonce  [NonceSize]byte // the current chunk's nonce, built in place
	err    error           // sticky terminal state (io.EOF on clean end)
	closed bool
}

// NewSpanReader returns a SpanReader that yields the plaintext bytes
// [start, end] (inclusive) of the stream whose complete ciphertext is
// ciphertextSize bytes long, reading the ciphertext from span. span must be
// positioned at the start of the contiguous range CiphertextRange reports
// for the same (ciphertextSize, chunkSize, start, end) — typically the
// body of a single range request for exactly that span. cfg must match the
// Writer that produced the stream, including the chunk size.
//
// start/end follow HTTP Range semantics (see ErrRange): an end past the
// last plaintext byte clamps; a negative start, an end before the start, or
// a start past the last byte returns ErrRange — there is no empty range.
// ciphertextSize must be a structurally valid stream length (else
// ErrCiphertextSize).
func NewSpanReader(span io.Reader, cfg Config, ciphertextSize, start, end int64) (*SpanReader, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	chunkSize := cfg.effectiveChunkSize()

	numChunks, lastCipherLen, plaintextLen, err := chunkLayout(ciphertextSize, chunkSize)
	if err != nil {
		return nil, err
	}
	if start < 0 || end < start || start > plaintextLen-1 {
		return nil, ErrRange
	}
	if end > plaintextLen-1 {
		end = plaintextLen - 1
	}
	total := end - start + 1

	aead, err := newGCM(cfg.Key)
	if err != nil {
		return nil, err
	}

	r := &SpanReader{
		aead:          aead,
		src:           span,
		aad:           append([]byte(nil), cfg.AAD...),
		chunkSize:     chunkSize,
		encChunk:      int64(chunkSize) + TagSize,
		numChunks:     numChunks,
		lastCipherLen: lastCipherLen,
		total:         total,
		remaining:     total,
		inBuf:         getBuf(chunkSize + TagSize),
		outBuf:        getBuf(chunkSize)[:0],
	}
	copy(r.base[:], cfg.BaseNonce)

	r.nextChunk = start / int64(chunkSize)
	r.skipFirst = int(start - r.nextChunk*int64(chunkSize))
	r.onFirst = true
	return r, nil
}

// Len returns the number of plaintext bytes this reader will emit in total
// — the requested length clamped to the bytes available from the offset.
// It is fixed at construction and does not change as bytes are read.
func (r *SpanReader) Len() int64 { return r.total }

// Close returns the SpanReader's chunk buffers to the pool (see pool.go).
// Further reads fail rather than return more plaintext. Close does not
// close the span. A SpanReader that is never closed is still collected
// normally; Close only lets the next stream reuse its buffers.
func (r *SpanReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	r.unread = nil
	r.err = errReadAfterClose
	putBuf(r.inBuf)
	putPlaintextBuf(r.outBuf)
	r.inBuf, r.outBuf = nil, nil
	return nil
}

// ChunkSize returns the plaintext chunk size in effect.
func (r *SpanReader) ChunkSize() int { return r.chunkSize }

// Read implements io.Reader. It returns the next bytes of the requested
// range, io.EOF once the whole range has been emitted, or one of the
// package's decryption errors.
func (r *SpanReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Serve buffered plaintext from the current chunk first.
	if len(r.unread) > 0 {
		n := copy(p, r.unread)
		r.unread = r.unread[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if err := r.nextSpanChunk(); err != nil {
		return 0, err
	}
	n := copy(p, r.unread)
	r.unread = r.unread[n:]
	// Unlike Reader.Read, no (n == 0 && r.err != nil) guard is needed here:
	// nextSpanChunk always yields at least one byte. It only runs while
	// remaining > 0, which implies start <= the last plaintext byte, so the
	// first chunk holds more plaintext than skipFirst trims, and every later
	// chunk in the range is non-empty by the stream geometry. (An empty
	// range never gets here — the constructor rejects it with ErrRange.)
	return n, nil
}

// nextSpanChunk reads, authenticates and decrypts the next chunk from the
// span, trims it to the requested range, and stores the result in r.unread.
// It records the terminal state in r.err (io.EOF once the range is
// exhausted) and returns a non-nil error only on a fatal condition.
func (r *SpanReader) nextSpanChunk() error {
	// The on-wire length and final-chunk flag come from the known stream
	// geometry — no probing, no retry.
	last := r.nextChunk == r.numChunks-1
	clen := r.encChunk
	if last {
		clen = r.lastCipherLen
	}

	if _, err := io.ReadFull(r.src, r.inBuf[:clen]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// The span ran out before the chunks the range needs: the caller
			// fetched too few bytes (or the wrong span). A fetch-side
			// problem, not stream corruption — hence not ErrTruncated.
			return r.fail(fmt.Errorf("aesstream: span ended before chunk %d: %w", r.nextChunk, ErrShortSpan))
		}
		return r.fail(fmt.Errorf("aesstream: read chunk %d: %w", r.nextChunk, err))
	}

	r.nonce = streamNonce(r.base, uint32(r.nextChunk), last)
	plain, err := r.aead.Open(r.outBuf[:0], r.nonce[:], r.inBuf[:clen], r.aad)
	if err != nil {
		return r.fail(ErrCorrupted)
	}

	// Trim the decrypted chunk to the part the caller asked for: drop the
	// leading bytes before the range start (only the first chunk), then cap
	// to the bytes still owed.
	if r.onFirst {
		plain = plain[r.skipFirst:]
		r.onFirst = false
	}
	if int64(len(plain)) > r.remaining {
		plain = plain[:r.remaining]
	}

	r.unread = plain
	r.remaining -= int64(len(plain))
	r.nextChunk++
	if r.remaining == 0 {
		// The range ends within this chunk; the next Read drains r.unread
		// and then sees io.EOF.
		r.err = io.EOF
	}
	return nil
}

// fail records err as the terminal state and returns it.
func (r *SpanReader) fail(err error) error {
	r.err = err
	return err
}

// OpenSpan decrypts the plaintext byte range [start, end] (inclusive) from a
// single contiguous ciphertext span and returns exactly those bytes. span
// carries the ciphertext range CiphertextRange reports for the same
// arguments (see NewSpanReader); OpenSpan is the one-shot convenience over
// SpanReader for callers that want the range in one buffer.
//
// start/end follow HTTP Range semantics (an over-long end clamps; see
// ErrRange), and like SpanReader.Read it reports tampering or reordering
// (ErrCorrupted) or a short span (ErrShortSpan) as a non-nil error, in which
// case the returned bytes must be discarded.
func OpenSpan(cfg Config, span io.Reader, ciphertextSize, start, end int64) ([]byte, error) {
	r, err := NewSpanReader(span, cfg, ciphertextSize, start, end)
	if err != nil {
		return nil, err
	}
	// OpenSpan buffers the whole range in memory. On a 64-bit platform
	// r.Len() always fits an int (it is bounded by the plaintext length),
	// but on a 32-bit build a multi-GiB range would overflow the int that
	// make wants and panic with "makeslice: len out of range" — return a
	// clear error instead, and steer such callers to the streaming reader.
	if r.Len() > math.MaxInt {
		return nil, fmt.Errorf("aesstream: range of %d bytes is too large to buffer; use NewSpanReader to stream", r.Len())
	}
	defer r.Close()
	buf := make([]byte, r.Len())
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
