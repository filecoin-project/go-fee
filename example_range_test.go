package fee_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"github.com/filecoin-project/go-fee"
)

// ExampleDecryptRange serves one byte range of an encrypted object the way an
// HTTP handler would: it derives the response's Content-Length and Content-Range
// from the reader before any ciphertext is fetched, then streams the range out.
func ExampleDecryptRange() {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	kid := []byte("did:key:zExampleRecipient#key-1")

	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	enc, err := fee.Encrypt(bytes.NewReader(plaintext),
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

	// A store hands over random access to the blob and its exact size; only the
	// envelope header and the chunks the range overlaps are ever read.
	const off, length = 4, 15
	r, err := fee.DecryptRange(bytes.NewReader(blob), int64(len(blob)),
		fee.NewECDHESUnwrapper(kid, priv), off, length)
	if err != nil {
		log.Fatal(err)
	}

	// Both are known up front, so a handler can write its headers before
	// decrypting a single chunk.
	fmt.Printf("Content-Length: %d\n", r.Len())
	fmt.Printf("Content-Range: bytes %d-%d/%d\n", off, off+r.Len()-1, r.Size())
	got, err := io.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("range: %q\n", got)

	// Output:
	// Content-Length: 15
	// Content-Range: bytes 4-18/43
	// range: "quick brown fox"
}
