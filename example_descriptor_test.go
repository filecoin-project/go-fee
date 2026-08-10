package fee_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"github.com/filecoin-project/go-fee"
	"github.com/filecoin-project/go-fee/aesstream"
)

// countingBlob is an io.ReaderAt that reports how many bytes were served from
// inside the envelope — the round trip a caching caller is trying to avoid.
type countingBlob struct {
	blob      *bytes.Reader
	headerLen int64
	envelope  int64 // bytes served from below headerLen
}

func (c *countingBlob) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.blob.ReadAt(p, off)
	if off < c.headerLen {
		c.envelope += min(int64(n), c.headerLen-off)
	}
	return n, err
}

// ExampleDecryptRangeWithDescriptor stores an object once and then serves a byte
// range of it without re-reading the envelope, the way a store that keeps
// metadata beside its blobs would: the writer records what
// [EncryptWithCEK] reports, and the reader rebuilds a decryptor from those
// columns alone.
func ExampleDecryptRangeWithDescriptor() {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	kid := []byte("did:key:zExampleRecipient#key-1")

	// The caller draws the CEK so it can wrap it under its own key-encryption
	// key; only the wrapped form is stored (omitted here for brevity).
	cek := make([]byte, aesstream.KeySize)
	if _, err := rand.Read(cek); err != nil {
		log.Fatal(err)
	}

	// The descriptor is complete before a byte is read, so a writer can record it
	// while the upload is still streaming.
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	enc, descriptor, err := fee.EncryptWithCEK(bytes.NewReader(plaintext), cek,
		[]fee.Recipient{fee.NewECDHESRecipient(kid, priv.PublicKey())},
		fee.WithContentLength(int64(len(plaintext))))
	if err != nil {
		log.Fatal(err)
	}

	blob, err := io.ReadAll(enc)
	if err != nil {
		log.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		log.Fatal(err)
	}

	// What a store persists alongside the blob's location: the descriptor, plus
	// the blob's exact size.
	row := struct {
		descriptor fee.BodyDescriptor
		blobSize   int64
	}{descriptor, int64(len(blob))}

	// Serving a range later. Nothing here decodes the envelope — the reader is
	// built from the stored row, so the only bytes fetched are ciphertext.
	src := &countingBlob{blob: bytes.NewReader(blob), headerLen: row.descriptor.HeaderLen}
	const off, length = 4, 15
	r, err := fee.DecryptRangeWithDescriptor(src, row.blobSize, row.descriptor, cek, off, length)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Content-Length: %d\n", r.Len())
	fmt.Printf("Content-Range: bytes %d-%d/%d\n", off, off+r.Len()-1, r.Size())

	got, err := io.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("range: %q\n", got)
	fmt.Printf("envelope bytes fetched: %d\n", src.envelope)

	// Output:
	// Content-Length: 15
	// Content-Range: bytes 4-18/43
	// range: "quick brown fox"
	// envelope bytes fetched: 0
}
