package fee

import (
	"errors"
	"fmt"
	"io"

	"github.com/filecoin-project/go-fee/aesstream"
	"github.com/filecoin-project/go-fee/cose"
)

// ErrSizeMismatch means the number of chunks the supplied blob size accounts for
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
// It is returned by [DecryptRange] and [DecryptRangeWithCEK], and reads
// ciphertext lazily: nothing beyond the envelope header is fetched until Read is
// called (nothing at all when [DecryptRangeWithCEK] is given a non-nil
// [BodyDescriptor], which reads no envelope), and then only the chunks the
// range overlaps.
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
	len  int64 // plaintext bytes this reader will emit
	size int64 // total plaintext size of the whole object

	spanStart int64 // blob-absolute first byte of the ciphertext span Read consumes
	spanEnd   int64 // blob-absolute last byte of that span (inclusive)
}

// Read implements io.Reader, yielding the requested plaintext range.
func (r *RangeReader) Read(p []byte) (int, error) {
	if r.sr == nil {
		return 0, io.EOF
	}
	return r.sr.Read(p)
}

// Close returns the reader's chunk buffers to the pool for reuse by the next
// stream (see [aesstream.SpanReader.Close]); reads after Close fail. It does
// not close the blob. A RangeReader that is never closed is still collected
// normally.
func (r *RangeReader) Close() error {
	if r.sr == nil {
		return nil
	}
	return r.sr.Close()
}

// Len returns the number of plaintext bytes this reader will emit: the
// requested range's length after end is clamped to the last plaintext byte.
// It is fixed at construction, so an HTTP consumer can use it as the response
// Content-Length before reading anything.
func (r *RangeReader) Len() int64 { return r.len }

// Size returns the total plaintext size of the whole object, derived from the
// blob size and the chunk size. It is the total an HTTP consumer puts after the
// slash in a Content-Range header. [BodyDescriptor.PlaintextSize] reports the
// same number from cached descriptor data, without a reader.
func (r *RangeReader) Size() int64 { return r.size }

// CiphertextSpan returns the blob-absolute, inclusive byte range [start, end]
// that Read will consume — the envelope header length plus the chunk-aligned
// ciphertext span the requested range overlaps.
//
// Because no ciphertext is read until the first Read, a caller backed by a remote
// store can construct the reader, fetch exactly this span in a single range
// request, and serve the reads from that buffer rather than letting each chunk
// become its own request.
func (r *RangeReader) CiphertextSpan() (start, end int64) { return r.spanStart, r.spanEnd }

// DecryptRange decrypts the inclusive plaintext byte range [start, end] of a FEE
// blob (envelope||ciphertext, as produced by [Encrypt]) without fetching or
// decrypting the whole object.
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
// start/end follow HTTP Range semantics: both inclusive, and an end past the
// last plaintext byte clamps — [RangeReader.Len] reports what will actually be
// emitted, so an open-ended HTTP range ("bytes=N-") can pass math.MaxInt64. An
// unsatisfiable range — a negative start, an end before the start, or a start
// past the last plaintext byte — fails with an error matching
// [aesstream.ErrRange] (an HTTP consumer's 416); there is no empty range. A
// blobSize that cannot be a FEE blob fails with [aesstream.ErrCiphertextSize],
// and one that contradicts the envelope's declared chunk count with
// [ErrSizeMismatch]. An envelope larger than 1 MiB is rejected as malformed.
//
// Every chunk the range overlaps is authenticated, so a tampered chunk surfaces
// as an error from Read rather than as corrupt plaintext. Chunks outside the range
// are never read and so never checked, and — unlike whole-object [Decrypt] — a
// range read cannot by itself detect that the stored object was truncated: an
// understated blobSize describes a shorter object whose ranges decrypt cleanly.
// The chunk-count check catches an understatement of a whole chunk or more when
// the envelope carries a count, but a size short by only part of the final chunk
// accounts for the same number of chunks and so passes it, surfacing instead as
// an authentication failure when that chunk is read. Whole-object integrity is
// properly the job of the layer that supplied blobSize.
func DecryptRange(blob io.ReaderAt, blobSize int64, unwrap RecipientUnwrapper, start, end int64) (*RangeReader, error) {
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

	return newRangeReader(env, blob, blobSize, headerLen, cek, start, end)
}

// DecryptRangeWithCEK is [DecryptRange] with a caller-provided content-encryption
// key instead of one recovered from an in-envelope recipient — for when the CEK
// was obtained out of band (e.g. unwrapped by a custody service). It accepts
// either a COSE_Encrypt (tag 96) or a recipient-less COSE_Encrypt0 (tag 16); any
// recipients are ignored. cek must be 32 bytes (AES-256).
//
// If desc is nil, it decodes the envelope header from blob exactly as
// [DecryptRange] does. A caller that already cached the needed
// envelope-derived metadata can pass it as desc to skip that header read
// entirely; the only bytes then fetched from blob are the ciphertext chunks the
// range overlaps. The descriptor is cloned before use, so later caller mutation
// cannot affect the decryptor built from it. A malformed descriptor is rejected
// up front with [ErrInvalidDescriptor]; a well-formed but stale or wrong one
// fails when read as [aesstream.ErrCorrupted], not as plausible plaintext.
//
// blobSize is the size of the whole stored blob, envelope included, exactly as
// for [DecryptRange]. When desc is non-nil there is no envelope to consult, so
// this path cannot perform the chunk-count cross-check that reports
// [ErrSizeMismatch] on the envelope-backed paths.
//
// The caller retains ownership of cek: it is copied into the body cipher but
// neither retained nor wiped by this call.
func DecryptRangeWithCEK(blob io.ReaderAt, blobSize int64, cek []byte, start, end int64, desc *BodyDescriptor) (*RangeReader, error) {
	if blob == nil {
		return nil, errNilBlob
	}

	if err := checkCEK(cek); err != nil {
		return nil, err
	}

	if desc != nil {
		// Validate the cached descriptor and derive plaintext size without
		// reading the envelope.
		var d BodyDescriptor = desc.clone()
		plainSize, err := d.PlaintextSize(blobSize)
		if err != nil {
			return nil, err
		}
		return spanRangeReader(blob, blobSize, d.HeaderLen, d.bodyParams(), d.aad(), plainSize, cek, start, end)
	}

	env, headerLen, err := decodeHeaderAt(blob, blobSize)
	if err != nil {
		return nil, err
	}
	return newRangeReader(env, blob, blobSize, headerLen, cek, start, end)
}

// PlaintextSize reports the total decrypted size of a FEE blob from its envelope
// header and blobSize alone. It reads only the header — no ciphertext — and needs
// no key material, so it answers a HEAD request, fills in the total of a
// Content-Range header, or resolves a suffix range ("bytes=-N" is
// start = size-N) without constructing a decryptor.
//
// It reports the same envelope, size and chunk-count errors as [DecryptRange].
func PlaintextSize(blob io.ReaderAt, blobSize int64) (int64, error) {
	env, headerLen, err := decodeHeaderAt(blob, blobSize)
	if err != nil {
		return 0, err
	}
	body, err := validateBodyParams(env)
	if err != nil {
		return 0, err
	}
	return envelopePlaintextSize(env, blobSize, headerLen, body.chunkSize)
}

// newRangeReader is the shared core of DecryptRange and the envelope-decoding
// branch of [DecryptRangeWithCEK]: given the decoded envelope, its encoded
// length, and the content-encryption key, it validates the body parameters,
// derives the stream geometry from the blob size, and wires the overlapping
// ciphertext span into a range reader.
//
// It does not retain cek past its own return: aesstream.NewSpanReader
// internalizes the CEK (into a GCM AEAD) synchronously, so a caller may wipe cek
// as soon as this returns — even though the reader decrypts lazily on later
// reads, which work from the internalized key, never the cek slice.
func newRangeReader(env *cose.Envelope, blob io.ReaderAt, blobSize, headerLen int64, cek []byte, start, end int64) (*RangeReader, error) {
	body, aad, err := buildBodyParamsWithAAD(env)
	if err != nil {
		return nil, err
	}

	plainSize, err := envelopePlaintextSize(env, blobSize, headerLen, body.chunkSize)
	if err != nil {
		return nil, err
	}
	return spanRangeReader(blob, blobSize, headerLen, body, aad, plainSize, cek, start, end)
}

// spanRangeReader is the geometry-and-wiring tail shared by the envelope-backed
// path ([newRangeReader]) and the cached-descriptor path (via a non-nil
// [BodyDescriptor] passed to [DecryptRangeWithCEK]): given the resolved body
// parameters and the object's plaintext size, it resolves the ciphertext span
// the range overlaps and hands exactly that span to the body cipher.
//
// The two paths differ only in how they arrive at body, aad and plainSize —
// decoded from the envelope, or supplied from a caller's cache — so keeping the
// wiring in one place is what makes them accept the same ranges and fail the
// same way.
func spanRangeReader(blob io.ReaderAt, blobSize, headerLen int64, body bodyParams, aad []byte, plainSize int64, cek []byte, start, end int64) (*RangeReader, error) {
	ciphertextSize := blobSize - headerLen

	ctStart, ctEnd, plainLen, err := aesstream.CiphertextRange(ciphertextSize, body.chunkSize, start, end)
	if err != nil {
		return nil, fmt.Errorf("fee: resolving ciphertext range: %w", err)
	}

	// The span is chunk-aligned and contiguous, so the section reader hands
	// aesstream exactly the bytes it will ask for and nothing else.
	sr, err := aesstream.NewSpanReader(
		io.NewSectionReader(blob, headerLen+ctStart, ctEnd-ctStart+1),
		body.streamConfig(cek, aad),
		ciphertextSize, start, end)
	if err != nil {
		return nil, fmt.Errorf("fee: initializing body cipher: %w", err)
	}

	return &RangeReader{sr: sr, len: plainLen, size: plainSize, spanStart: headerLen + ctStart, spanEnd: headerLen + ctEnd}, nil
}

// envelopePlaintextSize is [plaintextSizeFrom] for a blob whose parameters came
// from its envelope rather than from a caller's cache: it adds the cross-check of
// the envelope's declared chunk count against the chunks the ciphertext actually
// holds, when a count is present, catching a blob size that describes a different
// object than the envelope does.
//
// The comparison is against [aesstream.ChunkCount] rather than a count re-derived
// from the plaintext size, because a plaintext that is an exact multiple of the
// chunk size seals to either k chunks or k+1 (with an empty final chunk) and both
// decrypt identically. Deriving from the plaintext size would recognize only the
// first form and refuse the second, which the whole-object [Decrypt] path reads
// without complaint.
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
	want, err := aesstream.ChunkCount(blobSize-headerLen, chunkSize)
	if err != nil {
		return 0, fmt.Errorf("fee: blob of %d ciphertext bytes: %w", blobSize-headerLen, err)
	}
	if declared != want {
		return 0, fmt.Errorf("%w: envelope declares %d chunks, the ciphertext holds %d",
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
