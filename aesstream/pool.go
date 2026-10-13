package aesstream

import "sync"

// Chunk buffers are pooled by capacity. A stream needs two of them (one
// plaintext chunk, one sealed chunk), each ChunkSize bytes or a little more,
// and at the default chunk size that is half a mebibyte of zeroed allocation
// per stream: for a 4 KiB object it is the whole cost of the cipher. Every
// Writer, Reader, EncryptReader and SpanReader takes its buffers from the
// pool for its chunk size and returns them on Close, so a closed stream
// leaves no garbage and the next stream of the same chunk size allocates
// nothing. A stream that is never closed just lets the garbage collector
// take its buffers, as before.
//
// A plaintext buffer is wiped before it goes back: pooled memory outlives
// the stream that filled it, and the next holder must not be handed
// another stream's plaintext.
var bufPools sync.Map // capacity → *sync.Pool of *[]byte

func poolFor(size int) *sync.Pool {
	if p, ok := bufPools.Load(size); ok {
		return p.(*sync.Pool)
	}
	p, _ := bufPools.LoadOrStore(size, &sync.Pool{New: func() any {
		b := make([]byte, size)
		return &b
	}})
	return p.(*sync.Pool)
}

// getBuf returns a buffer of exactly size bytes, len and cap both size. Its
// contents are unspecified.
func getBuf(size int) []byte {
	return (*poolFor(size).Get().(*[]byte))[:size]
}

// putBuf returns b to the pool for its capacity. A nil b is ignored.
func putBuf(b []byte) {
	if cap(b) == 0 {
		return
	}
	b = b[:cap(b)]
	poolFor(cap(b)).Put(&b)
}

// putPlaintextBuf wipes b and returns it to the pool.
func putPlaintextBuf(b []byte) {
	if cap(b) == 0 {
		return
	}
	b = b[:cap(b)]
	clear(b)
	poolFor(cap(b)).Put(&b)
}
