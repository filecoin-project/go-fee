package aesstream

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
)

// errReadAfterClose is returned by EncryptReader.Read once Close has been
// called.
var errReadAfterClose = errors.New("aesstream: read after close")

// EncryptReader encrypts a plaintext stream into the chunked AES-256-GCM
// STREAM format and yields the ciphertext through an io.Reader. It is the
// pull-mode counterpart of Writer: where Writer is pushed plaintext and
// pushes ciphertext to a destination, EncryptReader pulls plaintext from a
// source as its consumer pulls ciphertext, so no goroutine or pipe stands
// between the two. The bytes it produces are identical to Writer's for the
// same Config and plaintext.
//
// Each chunk is filled straight from the source (one full chunk per
// io.ReadFull, however small the source's reads are), sealed in place, and
// served from the sealed buffer. WriteTo hands each sealed chunk to the
// destination as one write, so an io.Copy from an EncryptReader delivers
// ChunkSize+TagSize-byte writes rather than io.Copy's 32 KiB pieces.
//
// The final chunk is marked as the source reaches EOF: a full chunk is only
// known to be the last one once the source has been asked for more, so the
// reader looks one byte ahead and carries it into the next chunk. A source
// read error surfaces from Read (or WriteTo) and ends the stream before its
// final chunk, so the ciphertext produced so far is truncated and fails to
// decrypt rather than passing as a complete object.
//
// An EncryptReader is not safe for concurrent use.
type EncryptReader struct {
	aead      cipher.AEAD
	src       io.Reader
	base      [BaseNonceSize]byte
	aad       []byte
	chunkSize int

	buf     []byte // plaintext of the chunk being sealed, cap chunkSize
	sealBuf []byte // the sealed chunk, cap chunkSize+TagSize
	unread  []byte // sealed bytes not yet returned, a slice of sealBuf

	carry    [1]byte // the look-ahead byte that starts the next chunk
	hasCarry bool

	nonce [NonceSize]byte // the current chunk's nonce, built in place

	index     uint64 // index of the next chunk to seal
	maxChunks uint64 // overridable in tests; defaults to MaxChunks
	err       error  // sticky terminal state (io.EOF once the final chunk is sealed)
	closed    bool
}

// NewEncryptReader returns an EncryptReader that encrypts the plaintext
// read from src under cfg. It validates cfg (see Config) and returns the
// matching sentinel error if the key, base nonce or chunk size is invalid.
func NewEncryptReader(src io.Reader, cfg Config) (*EncryptReader, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	aead, err := newGCM(cfg.Key)
	if err != nil {
		return nil, err
	}
	chunkSize := cfg.effectiveChunkSize()
	// Copy AAD so the reader doesn't alias caller-owned memory: it is
	// authenticated on every chunk, so a later mutation or reuse of the
	// caller's slice must not change this stream's authentication.
	r := &EncryptReader{
		aead:      aead,
		src:       src,
		aad:       append([]byte(nil), cfg.AAD...),
		chunkSize: chunkSize,
		buf:       getBuf(chunkSize),
		sealBuf:   getBuf(chunkSize + TagSize)[:0],
		maxChunks: MaxChunks,
	}
	copy(r.base[:], cfg.BaseNonce)
	return r, nil
}

// Read implements io.Reader. It returns ciphertext, io.EOF once the final
// chunk has been returned in full, or the source's read error.
func (r *EncryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.unread) > 0 {
		n := copy(p, r.unread)
		r.unread = r.unread[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if err := r.nextChunk(); err != nil {
		return 0, err
	}
	n := copy(p, r.unread)
	r.unread = r.unread[n:]
	return n, nil
}

// WriteTo implements io.WriterTo: it seals chunks and writes each one to w
// in a single call. io.Copy prefers it, so a consumer receives whole
// sealed chunks. It returns the number of ciphertext bytes written and the
// first source read or destination write error.
func (r *EncryptReader) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for {
		if len(r.unread) > 0 {
			n := len(r.unread)
			err := writeAll(w, r.unread)
			r.unread = nil
			if err != nil {
				// Drop what was not written: a destination error ends the
				// stream and the consumer cannot resume it.
				r.err = err
				return total, err
			}
			total += int64(n)
		}
		if r.err != nil {
			if r.err == io.EOF {
				return total, nil
			}
			return total, r.err
		}
		if err := r.nextChunk(); err != nil {
			return total, err
		}
	}
}

// Close returns the reader's chunk buffers to the pool (see pool.go).
// Further reads fail rather than return more ciphertext. Close does not
// close the source.
func (r *EncryptReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	r.unread = nil
	r.err = errReadAfterClose
	putPlaintextBuf(r.buf)
	putBuf(r.sealBuf)
	r.buf, r.sealBuf = nil, nil
	return nil
}

// ChunkSize returns the plaintext chunk size in effect.
func (r *EncryptReader) ChunkSize() int { return r.chunkSize }

// nextChunk fills the next plaintext chunk from the source, decides whether
// it is the last, seals it into r.unread and advances the index. It
// records io.EOF in r.err once the final chunk is sealed, and any read
// error as the terminal state.
func (r *EncryptReader) nextChunk() error {
	if r.index >= r.maxChunks {
		return r.fail(ErrTooManyChunks)
	}
	buf := r.buf[:r.chunkSize]
	n := 0
	if r.hasCarry {
		buf[0] = r.carry[0]
		r.hasCarry = false
		n = 1
	}
	m, err := io.ReadFull(r.src, buf[n:])
	n += m

	var last bool
	switch err {
	case nil:
		// A full chunk. It is the last one only if the source is now at
		// EOF; otherwise the byte read here starts the next chunk. (The
		// one-byte buffer lives on the reader so the read does not
		// allocate per chunk.)
		switch k, lerr := io.ReadFull(r.src, r.carry[:]); {
		case k == 1:
			r.hasCarry = true
		case lerr == io.EOF:
			last = true
		default:
			return r.fail(fmt.Errorf("aesstream: read plaintext after chunk %d: %w", r.index, lerr))
		}
	case io.EOF, io.ErrUnexpectedEOF:
		// The source ran out inside this chunk: it is the (short or empty)
		// final chunk.
		last = true
	default:
		return r.fail(fmt.Errorf("aesstream: read plaintext chunk %d: %w", r.index, err))
	}

	// The nonce is built on the reader and Seal appends into sealBuf's
	// backing array, which is sized for one chunk, so no allocation
	// happens in steady state.
	r.nonce = streamNonce(r.base, uint32(r.index), last)
	r.sealBuf = r.aead.Seal(r.sealBuf[:0], r.nonce[:], buf[:n], r.aad)
	r.unread = r.sealBuf
	r.index++
	if last {
		r.err = io.EOF
	}
	return nil
}

// fail records err as the terminal state and returns it.
func (r *EncryptReader) fail(err error) error {
	r.err = err
	return err
}
