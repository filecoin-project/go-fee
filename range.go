package fee

import (
	"errors"
	"fmt"
	"io"

	"github.com/filecoin-project/go-fee/aesstream"
	"github.com/filecoin-project/go-fee/cose"
)

// ErrSizeMismatch means the ciphertext length implied by the supplied blob size
// disagrees with the chunk count the envelope declares: the blob is truncated or
// padded, or the size came from the wrong object.
//
// The chunk count rides in the unprotected header ([WithContentLength] writes it
// when the plaintext length is known), so it is not covered by the envelope AAD
// and an attacker rewriting the blob can strip or adjust it. This check therefore
// catches operational mistakes — a stale size in a store's metadata, a partially
// written object — and is not an integrity guarantee. Whole-object integrity must
// come from the layer that supplied the size (a CID, a signed manifest).
var ErrSizeMismatch = errors.New("fee: blob size disagrees with the envelope's declared chunk count")

// errNilBlob is reported by every range entry point that would otherwise read
// from a nil blob, whether or not it decodes an envelope first.
var errNilBlob = errors.New("fee: nil blob reader")

const (
	// headerProbeSize is the first prefix length the envelope-header probe
	// reads. A FEE envelope with a handful of recipients is a few hundred
	// bytes, so one read of this size decodes essentially every real blob.
	headerProbeSize = 4096

	// maxHeaderLen bounds the probe's growth, so a blob whose prefix declares
	// an enormous CBOR item cannot make the probe allocate its way up to the
	// full blob size. It still admits thousands of recipients (a recipient
	// entry is a couple of hundred bytes).
	maxHeaderLen = 1 << 20
)

// RangeReader streams the decrypted plaintext of one byte range of a FEE blob.
// It is returned by [DecryptRange], [DecryptRangeWithCEK] and
// [DecryptRangeWithMaterial], and reads ciphertext lazily: nothing beyond the
// envelope header is fetched until Read is called (nothing at all on the cached
// material path, which reads no envelope), and then only the chunks the range
// overlaps.
//
// Any non-EOF error from Read means the plaintext emitted so far is incomplete
// and must be discarded — a tampered or reordered chunk surfaces as
// [aesstream.ErrCorrupted], and a blob that ends before the range's chunks do as
// [aesstream.ErrShortSpan]. A clean io.EOF means the whole requested range was
// emitted.
//
// A RangeReader is not safe for concurrent use.
type RangeReader struct {
	sr   *aesstream.SpanReader
	size int64 // total plaintext size of the whole object

	spanOff int64 // blob-absolute offset of the ciphertext span Read consumes
	spanLen int64 // byte length of that span (0 for an empty range)
}

// Read implements io.Reader, yielding the requested plaintext range.
func (r *RangeReader) Read(p []byte) (int, error) { return r.sr.Read(p) }

// Len returns the number of plaintext bytes this reader will emit: the requested
// length clamped to the bytes available from the offset. It is fixed at
// construction, so an HTTP consumer can use it as the response Content-Length
// before reading anything.
func (r *RangeReader) Len() int64 { return r.sr.Len() }

// Size returns the total plaintext size of the whole object, derived from the
// blob size and the chunk size. It is the total an HTTP consumer puts after the
// slash in a Content-Range header. [BodyMaterial.PlaintextSize] reports the same
// number from cached material, without a reader.
func (r *RangeReader) Size() int64 { return r.size }

// CiphertextSpan returns the blob-absolute byte range [off, off+n) that Read will
// consume — the envelope header length plus the chunk-aligned ciphertext span the
// requested range overlaps. n is 0 for an empty range, in which case no
// ciphertext is read at all.
//
// Because no ciphertext is read until the first Read, a caller backed by a remote
// store can construct the reader, fetch exactly this span in a single range
// request, and serve the reads from that buffer rather than letting each chunk
// become its own request.
func (r *RangeReader) CiphertextSpan() (off, n int64) { return r.spanOff, r.spanLen }

// DecryptRange decrypts the plaintext byte range [off, off+length) of a FEE blob
// (envelope||ciphertext, as produced by [Encrypt]) without fetching or decrypting
// the whole object.
//
// blob is random access over the stored bytes and blobSize is their exact total
// length, as the store reports it. The STREAM geometry — chunk boundaries, which
// chunk is final, the total plaintext size — is derived from blobSize, so it must
// be correct; see the accuracy note below. Only the envelope header and the
// ciphertext chunks the range overlaps are read: one small ReadAt at offset 0 to
// decode the header (rarely a second, larger one for an unusually big envelope),
// then, driven by Read, one ReadAt per overlapping chunk at contiguous ascending
// offsets covering exactly [RangeReader.CiphertextSpan]. No ciphertext is read
// before the first Read, so a caller fronting a remote store may prefetch that
// span in a single range request.
//
// unwrap locates and recovers the content-encryption key exactly as [Decrypt]
// does: a recipient-less COSE_Encrypt0 yields [ErrNoRecipientsInEnvelope] (use
// [DecryptRangeWithCEK]), no recipient kid matching unwrap yields
// [ErrNoMatchingRecipient] without attempting an unwrap, and a matched recipient
// whose wrapped CEK cannot be recovered returns the unwrap error.
//
// length is clamped to the bytes available from off — [RangeReader.Len] reports
// what will actually be emitted, so an open-ended HTTP range can pass
// math.MaxInt64. off may equal the plaintext size (an empty range), but a larger
// off, or a negative off or length, fails with an error matching
// [aesstream.ErrRange] (an HTTP consumer's 416). A blobSize that cannot be a FEE
// blob fails with [aesstream.ErrCiphertextSize], and one that contradicts the
// envelope's declared chunk count with [ErrSizeMismatch]. An envelope larger than
// 1 MiB is rejected as malformed.
//
// Every chunk the range overlaps is authenticated, so a tampered chunk surfaces
// as an error from Read rather than as corrupt plaintext. Chunks outside the range
// are never read and so never checked, and — unlike whole-object [Decrypt] — a
// range read cannot by itself detect that the stored object was truncated: an
// understated blobSize describes a shorter object whose ranges decrypt cleanly.
// The chunk-count check catches that when the envelope carries a chunk count, but
// whole-object integrity is properly the job of the layer that supplied blobSize.
func DecryptRange(blob io.ReaderAt, blobSize int64, unwrap RecipientUnwrapper, off, length int64) (*RangeReader, error) {
	if unwrap == nil {
		return nil, ErrNilUnwrapper
	}
	env, headerLen, err := decodeHeaderAt(blob, blobSize)
	if err != nil {
		return nil, err
	}
	if len(env.Recipients) == 0 {
		return nil, ErrNoRecipientsInEnvelope
	}

	match, err := matchRecipient(env.Recipients, unwrap.keyID())
	if err != nil {
		return nil, err
	}
	cek, err := unwrap.unwrap(match)
	if err != nil {
		return nil, err
	}
	// The recovered CEK is ours; wipe it once newRangeReader has copied it into
	// the body cipher (synchronously, before it returns).
	defer zero(cek)

	return newRangeReader(env, blob, blobSize, headerLen, cek, off, length)
}

// DecryptRangeWithCEK is [DecryptRange] with a caller-provided content-encryption
// key instead of one recovered from an in-envelope recipient — for when the CEK
// was obtained out of band (e.g. unwrapped by a custody service). It accepts
// either a COSE_Encrypt (tag 96) or a recipient-less COSE_Encrypt0 (tag 16); any
// recipients are ignored. cek must be 32 bytes (AES-256).
//
// The caller retains ownership of cek: it is copied into the body cipher but
// neither retained nor wiped by this call.
func DecryptRangeWithCEK(blob io.ReaderAt, blobSize int64, cek []byte, off, length int64) (*RangeReader, error) {
	if err := checkCEK(cek); err != nil {
		return nil, err
	}
	env, headerLen, err := decodeHeaderAt(blob, blobSize)
	if err != nil {
		return nil, err
	}
	return newRangeReader(env, blob, blobSize, headerLen, cek, off, length)
}

// DecryptRangeWithMaterial is [DecryptRangeWithCEK] for a caller that already
// holds the envelope's parameters, as [Encrypt] reports them at encryption time.
// Unlike every other entry point here it reads no envelope at all: the only
// bytes fetched from blob are the ciphertext chunks the range overlaps, so
// a caller fronting a remote object store spends no round trip re-reading a
// header it has already seen.
//
// m must describe this blob. A value that cannot describe any FEE body is
// rejected up front with [ErrIncompleteMaterial]; one that is well-formed but
// belongs to a different object, or has drifted from the bytes on disk, is caught
// by the body cipher instead — BaseNonce and AAD are bound into every chunk's
// tag, so the read fails with [aesstream.ErrCorrupted] rather than emitting wrong
// plaintext.
//
// blobSize is the whole stored object, envelope included, exactly as for
// [DecryptRange]. Because there is no envelope to consult, the declared
// chunk-count cross-check that yields [ErrSizeMismatch] on the other paths cannot
// run here: nothing detects a blobSize that disagrees with the stored object.
// A caller that records the blob's size alongside this material should compare
// the two before trusting a range, since a size from a store that has silently
// lost bytes reads as a shorter object whose interior ranges decrypt cleanly (see
// the accuracy note on [DecryptRange]).
//
// cek must be 32 bytes (AES-256). The caller retains ownership: it is copied into
// the body cipher but neither retained nor wiped. off and length behave exactly
// as in [DecryptRange].
func DecryptRangeWithMaterial(blob io.ReaderAt, blobSize int64, m BodyMaterial, cek []byte, off, length int64) (*RangeReader, error) {
	if err := checkCEK(cek); err != nil {
		return nil, err
	}
	if blob == nil {
		return nil, errNilBlob
	}
	plainSize, err := m.PlaintextSize(blobSize) // validates m, and blobSize against it
	if err != nil {
		return nil, err
	}
	return spanRangeReader(blob, blobSize, m.HeaderLen, m.body(), plainSize, cek, off, length)
}

// PlaintextSize reports the total decrypted size of a FEE blob from its envelope
// header and blobSize alone. It reads only the header — no ciphertext — and needs
// no key material, so it answers a HEAD request, fills in the total of a
// Content-Range header, or resolves a suffix range ("bytes=-N" is off = size-N)
// without constructing a decryptor.
//
// It reports the same envelope, size and chunk-count errors as [DecryptRange].
func PlaintextSize(blob io.ReaderAt, blobSize int64) (int64, error) {
	env, headerLen, err := decodeHeaderAt(blob, blobSize)
	if err != nil {
		return 0, err
	}
	body, err := validateBody(env)
	if err != nil {
		return 0, err
	}
	return envelopePlaintextSize(env, blobSize, headerLen, body.chunkSize)
}

// newRangeReader is the shared core of DecryptRange and DecryptRangeWithCEK:
// given the decoded envelope, its encoded length, and the content-encryption key,
// it validates the body parameters, derives the stream geometry from the blob
// size, and wires the overlapping ciphertext span into a range reader.
//
// It does not retain cek past its own return: aesstream.NewSpanReader
// internalizes the CEK (into a GCM AEAD) synchronously, so a caller may wipe cek
// as soon as this returns — even though the reader decrypts lazily on later
// reads, which work from the internalized key, never the cek slice.
func newRangeReader(env *cose.Envelope, blob io.ReaderAt, blobSize, headerLen int64, cek []byte, off, length int64) (*RangeReader, error) {
	body, err := validateBody(env)
	if err != nil {
		return nil, err
	}

	plainSize, err := envelopePlaintextSize(env, blobSize, headerLen, body.chunkSize)
	if err != nil {
		return nil, err
	}
	return spanRangeReader(blob, blobSize, headerLen, body, plainSize, cek, off, length)
}

// spanRangeReader is the geometry-and-wiring tail shared by the envelope-backed
// path ([newRangeReader]) and the cached-material path
// ([DecryptRangeWithMaterial]): given the resolved body parameters and the
// object's plaintext size, it resolves the ciphertext span the range overlaps and
// hands exactly that span to the body cipher.
//
// The two paths differ only in how they arrive at body and plainSize — decoded
// from the envelope, or supplied from a caller's cache — so keeping the wiring in
// one place is what makes them accept the same ranges and fail the same way.
func spanRangeReader(blob io.ReaderAt, blobSize, headerLen int64, body bodyParams, plainSize int64, cek []byte, off, length int64) (*RangeReader, error) {
	ciphertextSize := blobSize - headerLen

	start, n, _, err := aesstream.CiphertextRange(ciphertextSize, body.chunkSize, off, length)
	if err != nil {
		return nil, fmt.Errorf("fee: resolving ciphertext range: %w", err)
	}

	// The span is chunk-aligned and contiguous, so the section reader hands
	// aesstream exactly the bytes it will ask for and nothing else.
	sr, err := aesstream.NewSpanReader(
		io.NewSectionReader(blob, headerLen+start, n),
		body.streamConfig(cek),
		ciphertextSize, off, length)
	if err != nil {
		return nil, fmt.Errorf("fee: initializing body cipher: %w", err)
	}

	return &RangeReader{sr: sr, size: plainSize, spanOff: headerLen + start, spanLen: n}, nil
}

// envelopePlaintextSize is [plaintextSizeFrom] for a blob whose parameters came
// from its envelope rather than from a caller's cache: it adds the cross-check of
// the envelope's declared chunk count against the derived size, when one is
// present, catching a blob size that describes a different object than the
// envelope does.
func envelopePlaintextSize(env *cose.Envelope, blobSize, headerLen int64, chunkSize int) (int64, error) {
	plainSize, err := plaintextSizeFrom(blobSize, headerLen, chunkSize)
	if err != nil {
		return 0, err
	}
	if !env.Headers.Unprotected.Has(labelChunkCount) {
		return plainSize, nil
	}
	declared, ok := env.Headers.Unprotected.Int(labelChunkCount)
	if !ok {
		return 0, fmt.Errorf("%w: chunk-count header is present but not an integer", ErrMalformedEnvelope)
	}
	if want := chunkCountFor(plainSize, int64(chunkSize)); declared != want {
		return 0, fmt.Errorf("%w: envelope declares %d chunks, the blob size implies %d",
			ErrSizeMismatch, declared, want)
	}
	return plainSize, nil
}

// decodeHeaderAt decodes the FEE envelope at the front of blob and reports its
// exact encoded length, so the caller can locate the detached ciphertext that
// follows it.
//
// A COSE envelope is a self-delimiting CBOR item, so cose.Decode over a prefix
// reports how many bytes it consumed (as the remainder it hands back) — but the
// prefix has to be long enough to hold the whole item. This reads a small prefix
// and, only if that turns out to be too short, doubles it and retries, up to
// maxHeaderLen. Every realistic envelope decodes on the first read.
func decodeHeaderAt(blob io.ReaderAt, blobSize int64) (*cose.Envelope, int64, error) {
	if blob == nil {
		return nil, 0, errNilBlob
	}
	if blobSize < 0 {
		return nil, 0, fmt.Errorf("fee: negative blob size %d", blobSize)
	}

	limit := min(blobSize, int64(maxHeaderLen))
	probe := min(int64(headerProbeSize), limit)
	for {
		buf := make([]byte, probe)
		n, rerr := blob.ReadAt(buf, 0)
		if rerr != nil && rerr != io.EOF {
			return nil, 0, fmt.Errorf("fee: reading envelope header: %w", rerr)
		}
		// A short read means the blob really ends here, whatever blobSize
		// claimed, so growing the probe cannot produce more bytes.
		atEnd := rerr == io.EOF || int64(n) < probe

		env, rest, derr := cose.Decode(buf[:n], cose.WithExpectedType(EnvelopeType))
		if derr == nil {
			return env, int64(n - len(rest)), nil
		}
		// Only a prefix that stopped mid-item is worth re-reading. Every other
		// decode failure — not a COSE tag, wrong typ, a duplicate header label —
		// was decided on complete bytes, so a longer prefix reaches the same
		// verdict. Retrying those would turn one wrong object id into a walk up to
		// maxHeaderLen against the store.
		if !errors.Is(derr, io.ErrUnexpectedEOF) || atEnd || probe >= limit {
			return nil, 0, fmt.Errorf("fee: decoding envelope: %w", derr)
		}
		probe = min(probe*2, limit)
	}
}
