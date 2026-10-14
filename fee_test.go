package fee_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"strconv"
	"testing"
	"testing/iotest"

	"github.com/filecoin-project/go-fee"
	"github.com/filecoin-project/go-fee/aeskw"
	"github.com/filecoin-project/go-fee/aesstream"
	"github.com/filecoin-project/go-fee/cose"
	"github.com/filecoin-project/go-fee/ecdhkw"
	"github.com/stretchr/testify/require"
)

// FEE wire constants mirrored for white-box assertions. They MUST match the
// unexported values in fee.go (and FIP-1253): the body algorithm and the
// protected header labels carrying the STREAM geometry and application
// metadata. Tests read them straight off a produced envelope with the cose
// package, so a drift in either place surfaces here.
const (
	algChunkedStream     = int64(-65793)
	labelChunkSize       = int64(-1)
	labelPlaintextLength = int64(-65789)
	labelAppMetadata     = int64(-65792)
)

// COSE_Key parameter labels/values for the X25519 ephemeral key (RFC 9053 §7.1),
// used to assert and to hand-build the self-describing ephemeral key.
const (
	coseKeyKty    = int64(1)
	coseKeyCrv    = int64(-1)
	coseKeyX      = int64(-2)
	coseKtyOKP    = int64(1)
	coseCrvX25519 = int64(4)
)

// ecdhKID and a256kwKID are opaque recipient key ids. In the app that will use
// this library a kid is a DID verification method ID; the library treats it as
// arbitrary bytes, so the tests use readable placeholders.
var (
	ecdhKID   = []byte("did:key:z6MkExampleRecipient#key-1")
	a256kwKID = []byte("did:example:custody#kek-1")
)

// newX25519Key returns a fresh X25519 keypair for an ECDH-ES recipient.
// Round-trip tests do not need determinism, so keys are generated per test.
func newX25519Key(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv
}

// newKEK returns a fresh 32-byte (A256KW) key-encryption key.
func newKEK(t *testing.T) []byte {
	t.Helper()
	kek := make([]byte, 32)
	_, err := rand.Read(kek)
	require.NoError(t, err)
	return kek
}

// newCEK returns a fresh 32-byte (AES-256) content-encryption key.
func newCEK(t *testing.T) []byte {
	t.Helper()
	cek := make([]byte, aesstream.KeySize)
	_, err := rand.Read(cek)
	require.NoError(t, err)
	return cek
}

// patternBytes returns n deterministic bytes whose period (251, prime) does not
// align to any power-of-two chunk size, so chunk boundaries fall on varying
// byte values.
func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// encrypt runs fee.Encrypt over plaintext and reads the streamed
// envelope||ciphertext into a single blob, so tests can inspect or corrupt it.
// An Encrypt setup error (e.g. an invalid recipient) is returned directly.
func encrypt(t *testing.T, plaintext []byte, recipients []fee.Recipient, opts ...fee.EncryptOption) ([]byte, error) {
	t.Helper()
	r, _, err := fee.Encrypt(bytes.NewReader(plaintext), recipients, opts...)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// decryptAll decrypts blob and reads the whole plaintext, asserting a clean
// stream (EOF, no decryption error).
func decryptAll(t *testing.T, blob []byte, u fee.RecipientUnwrapper) []byte {
	t.Helper()
	r, err := fee.Decrypt(bytes.NewReader(blob), u)
	require.NoError(t, err)
	plaintext, err := io.ReadAll(r)
	require.NoError(t, err)
	return plaintext
}

// TestRoundTripECDHES exercises the ECDH-ES+A256KW recipient path across a range
// of sizes — empty, sub-chunk, chunk boundaries and multi-chunk — at a small
// chunk size so the multi-chunk STREAM path runs cheaply.
func TestRoundTripECDHES(t *testing.T) {
	const chunk = aesstream.MinChunkSize // 4 KiB

	sizes := []int{0, 1, 100, chunk - 1, chunk, chunk + 1, 3*chunk + 7}
	for _, n := range sizes {
		n := n
		t.Run(name(n), func(t *testing.T) {
			key := newX25519Key(t)
			plaintext := patternBytes(n)

			blob, err := encrypt(t, plaintext,
				[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
				fee.WithChunkSize(chunk),
			)
			require.NoError(t, err)

			got := decryptAll(t, blob, fee.NewECDHESUnwrapper(ecdhKID, key))
			require.Equal(t, plaintext, got)
		})
	}
}

// TestRoundTripA256KW exercises the A256KW recipient path (under a raw KEK),
// including a multi-chunk body, at the default chunk size to confirm the default
// round-trips without WithChunkSize.
func TestRoundTripA256KW(t *testing.T) {
	kek := newKEK(t)
	plaintext := patternBytes(300_000) // > 256 KiB default chunk: multiple chunks

	blob, err := encrypt(t, plaintext,
		[]fee.Recipient{fee.NewA256KWRecipient(a256kwKID, kek)},
	)
	require.NoError(t, err)

	got := decryptAll(t, blob, fee.NewA256KWUnwrapper(a256kwKID, kek))
	require.Equal(t, plaintext, got)
}

// TestRoundTripMixedRecipients is a central acceptance criterion: one Encrypt
// call with both an ECDH-ES and an A256KW recipient yields an envelope that
// either recipient can open on its own, recovering the same plaintext — and the
// caller never selects a wrap algorithm.
func TestRoundTripMixedRecipients(t *testing.T) {
	key := newX25519Key(t)
	kek := newKEK(t)
	plaintext := patternBytes(20_000)

	blob, err := encrypt(t, plaintext,
		[]fee.Recipient{
			fee.NewECDHESRecipient(ecdhKID, key.PublicKey()),
			fee.NewA256KWRecipient(a256kwKID, kek),
		},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)

	t.Run("ECDH-ES opens", func(t *testing.T) {
		require.Equal(t, plaintext, decryptAll(t, blob, fee.NewECDHESUnwrapper(ecdhKID, key)))
	})
	t.Run("A256KW opens", func(t *testing.T) {
		require.Equal(t, plaintext, decryptAll(t, blob, fee.NewA256KWUnwrapper(a256kwKID, kek)))
	})
}

// encryptAndRecoverCEK encrypts plaintext to key and returns the envelope blob,
// the CEK actually used (unwrapped from the envelope's ECDH-ES recipient) and the
// envelope's base nonce.
func encryptAndRecoverCEK(t *testing.T, key *ecdh.PrivateKey, plaintext []byte) (blob, cek, baseNonce []byte) {
	t.Helper()

	var err error
	blob, err = encrypt(t, plaintext,
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
	)
	require.NoError(t, err)

	env, _, err := cose.Decode(blob, cose.WithExpectedType(fee.EnvelopeType))
	require.NoError(t, err)

	var ok bool
	baseNonce, ok = env.Headers.Protected.Bytes(cose.HeaderLabelIV)
	require.True(t, ok, "base nonce present in the protected header")

	require.Len(t, env.Recipients, 1)
	rcpt := env.Recipients[0]
	ephRaw, ok := rcpt.Headers.Unprotected.Get(cose.HeaderLabelEphemeralKey)
	require.True(t, ok, "ECDH-ES recipient carries an ephemeral key")
	eph, ok := ephRaw.(map[any]any)
	require.True(t, ok, "ephemeral key is a self-describing COSE_Key map")
	x, ok := eph[coseKeyX].([]byte)
	require.True(t, ok, "ephemeral key x is a byte string")
	ephPub, err := ecdh.X25519().NewPublicKey(x)
	require.NoError(t, err)

	protected, err := rcpt.Headers.ProtectedBytes()
	require.NoError(t, err)

	cek, err = ecdhkw.Unwrap(key, &ecdhkw.Wrapped{
		EphemeralPublicKey: ephPub,
		WrappedCEK:         rcpt.Ciphertext,
	}, protected)
	require.NoError(t, err, "ECDH-ES+A256KW unwrap")

	return blob, cek, baseNonce
}

// TestEncryptFreshCEKPerObject confirms Encrypt derives a fresh CEK and base
// nonce for every call, so no (key, nonce) pair is ever reused across objects.
// The CEKs are recovered by unwrapping the recipient entry: comparing
// ciphertexts alone would also pass with a fixed CEK and a fresh base nonce.
func TestEncryptFreshCEKPerObject(t *testing.T) {
	key := newX25519Key(t)
	plaintext := patternBytes(100)

	blob1, cek1, nonce1 := encryptAndRecoverCEK(t, key, plaintext)
	_, cek2, nonce2 := encryptAndRecoverCEK(t, key, plaintext)

	t.Run("CEK differs across Encrypt calls", func(t *testing.T) {
		require.NotEqual(t, cek1, cek2)
	})

	t.Run("base nonce differs across Encrypt calls", func(t *testing.T) {
		require.NotEqual(t, nonce1, nonce2)
	})

	t.Run("unwrapped CEK opens the body", func(t *testing.T) {
		dr, err := fee.DecryptWithCEK(bytes.NewReader(blob1), cek1)
		require.NoError(t, err)
		got, err := io.ReadAll(dr)
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
	})
}

// TestExternalCEK exercises the externally-provided-CEK path with a recipient
// still present: EncryptWithCEK seals under a caller-held CEK (producing a tag-96
// COSE_Encrypt that also carries the wrapped CEK) and DecryptWithCEK recovers
// with it, ignoring recipients. It also cross-checks that the in-envelope
// recipient unwraps to the very CEK that was used, and that a wrong CEK fails.
func TestExternalCEK(t *testing.T) {
	cek := newCEK(t)
	kek := newKEK(t)
	plaintext := patternBytes(3*aesstream.MinChunkSize + 5)

	// Seal under the caller's CEK; still carry an A256KW recipient so the CEK is
	// recoverable in-envelope too.
	enc, _, err := fee.EncryptWithCEK(bytes.NewReader(plaintext), cek,
		[]fee.Recipient{fee.NewA256KWRecipient(a256kwKID, kek)},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)
	defer enc.Close()
	blob, err := io.ReadAll(enc)
	require.NoError(t, err)

	// With a recipient present it is a tag-96 COSE_Encrypt.
	tag, err := cose.PeekTag(blob)
	require.NoError(t, err)
	require.Equal(t, cose.TagCOSEEncrypt, tag)

	t.Run("DecryptWithCEK recovers", func(t *testing.T) {
		dr, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
		require.NoError(t, err)
		got, err := io.ReadAll(dr)
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
	})

	t.Run("in-envelope recipient unwraps the same CEK", func(t *testing.T) {
		require.Equal(t, plaintext, decryptAll(t, blob, fee.NewA256KWUnwrapper(a256kwKID, kek)))
	})

	t.Run("wrong CEK fails on read", func(t *testing.T) {
		dr, err := fee.DecryptWithCEK(bytes.NewReader(blob), newCEK(t))
		require.NoError(t, err, "the CEK is not authenticated until the body is read")
		_, err = io.ReadAll(dr)
		require.ErrorIs(t, err, aesstream.ErrCorrupted)
	})
}

// TestExternalCEKNoRecipients exercises the recipient-less path: EncryptWithCEK
// with no recipients emits a COSE_Encrypt0 (tag 16) that DecryptWithCEK recovers,
// while the in-envelope Decrypt refuses it (there is no wrapped CEK to unwrap).
func TestExternalCEKNoRecipients(t *testing.T) {
	cek := newCEK(t)
	plaintext := patternBytes(2*aesstream.MinChunkSize + 3)

	enc, _, err := fee.EncryptWithCEK(bytes.NewReader(plaintext), cek, nil,
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)
	defer enc.Close()
	blob, err := io.ReadAll(enc)
	require.NoError(t, err)

	// A recipient-less envelope is a COSE_Encrypt0 (tag 16).
	tag, err := cose.PeekTag(blob)
	require.NoError(t, err)
	require.Equal(t, cose.TagCOSEEncrypt0, tag)

	t.Run("DecryptWithCEK recovers", func(t *testing.T) {
		dr, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
		require.NoError(t, err)
		got, err := io.ReadAll(dr)
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
	})

	t.Run("Decrypt refuses a recipient-less envelope", func(t *testing.T) {
		r, err := fee.Decrypt(bytes.NewReader(blob), fee.NewA256KWUnwrapper(a256kwKID, newKEK(t)))
		require.Nil(t, r)
		require.ErrorIs(t, err, fee.ErrNoRecipientsInEnvelope)
	})
}

// TestExternalCEKInvalidLength confirms both external-CEK entry points reject a
// CEK that is not 32 bytes.
func TestExternalCEKInvalidLength(t *testing.T) {
	t.Run("encrypt", func(t *testing.T) {
		_, _, err := fee.EncryptWithCEK(bytes.NewReader(patternBytes(10)), make([]byte, 16),
			[]fee.Recipient{fee.NewA256KWRecipient(a256kwKID, newKEK(t))})
		require.ErrorIs(t, err, fee.ErrInvalidCEK)
	})
	t.Run("decrypt", func(t *testing.T) {
		r, err := fee.DecryptWithCEK(bytes.NewReader([]byte{0xd8, 0x60}), make([]byte, 16))
		require.Nil(t, r)
		require.ErrorIs(t, err, fee.ErrInvalidCEK)
	})
}

// TestStreamingRoundTrip pipes Encrypt's reader straight into Decrypt with no
// intermediate []byte, so the whole object flows reader→reader. This exercises
// cose.DecodeReader parsing the header off a live stream and the ciphertext
// being streamed from the same source.
func TestStreamingRoundTrip(t *testing.T) {
	key := newX25519Key(t)
	plaintext := patternBytes(3*aesstream.MinChunkSize + 123)

	enc, _, err := fee.Encrypt(
		bytes.NewReader(plaintext),
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)
	defer enc.Close()

	dec, err := fee.Decrypt(enc, fee.NewECDHESUnwrapper(ecdhKID, key))
	require.NoError(t, err)

	got, err := io.ReadAll(dec)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// TestDecryptFromFragmentedReader decrypts an envelope whose bytes arrive one at
// a time, confirming the streaming header decode reassembles correctly when the
// detached ciphertext is split between the decoder's read-ahead buffer and the
// source reader.
func TestDecryptFromFragmentedReader(t *testing.T) {
	key := newX25519Key(t)
	plaintext := patternBytes(2*aesstream.MinChunkSize + 7)
	blob, err := encrypt(t, plaintext,
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)

	dec, err := fee.Decrypt(iotest.OneByteReader(bytes.NewReader(blob)), fee.NewECDHESUnwrapper(ecdhKID, key))
	require.NoError(t, err)
	got, err := io.ReadAll(dec)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// TestEncryptReaderCloseReleases confirms the reader can be closed after a
// partial read without deadlocking, and that reads after close fail rather than
// return the full ciphertext (the background encryption goroutine is aborted).
func TestEncryptReaderCloseReleases(t *testing.T) {
	key := newX25519Key(t)
	// Large enough that the encryption goroutine would block on the pipe if the
	// reader were abandoned without Close.
	enc, _, err := fee.Encrypt(
		bytes.NewReader(patternBytes(10*aesstream.MinChunkSize)),
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)

	buf := make([]byte, 16)
	_, _ = enc.Read(buf) // consume a little
	require.NoError(t, enc.Close())

	// After Close the stream is aborted; draining the rest must error, not hang.
	_, err = io.ReadAll(enc)
	require.Error(t, err)
}

// TestDecryptKidMismatch covers the explicit acceptance criterion: an unwrapper
// whose key id matches no recipient yields ErrNoMatchingRecipient rather than a
// panic or a silent failure, without trying the key. It checks both recipient
// kinds.
func TestDecryptKidMismatch(t *testing.T) {
	plaintext := patternBytes(5000)

	t.Run("ECDH-ES unwrapper, wrong kid", func(t *testing.T) {
		key := newX25519Key(t)
		blob, err := encrypt(t, plaintext,
			[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
			fee.WithChunkSize(aesstream.MinChunkSize),
		)
		require.NoError(t, err)

		r, err := fee.Decrypt(bytes.NewReader(blob), fee.NewECDHESUnwrapper([]byte("other-kid"), key))
		require.Nil(t, r)
		require.ErrorIs(t, err, fee.ErrNoMatchingRecipient)
	})

	t.Run("A256KW unwrapper, wrong kid", func(t *testing.T) {
		kek := newKEK(t)
		blob, err := encrypt(t, plaintext,
			[]fee.Recipient{fee.NewA256KWRecipient([]byte("kid-a"), kek)},
			fee.WithChunkSize(aesstream.MinChunkSize),
		)
		require.NoError(t, err)

		// The KEK is right, but a key with a different kid is never tried.
		r, err := fee.Decrypt(bytes.NewReader(blob), fee.NewA256KWUnwrapper([]byte("kid-b"), kek))
		require.Nil(t, r)
		require.ErrorIs(t, err, fee.ErrNoMatchingRecipient)
		require.NotErrorIs(t, err, aeskw.ErrIntegrity)
	})
}

// TestDecryptWrongECDHKey confirms that when the kid matches but the private key
// is wrong, the ECDH-ES unwrap fails the AES-KW integrity check, so no
// recipient can be unwrapped, and no plaintext reader is produced — decryption
// is never reached.
func TestDecryptWrongECDHKey(t *testing.T) {
	key := newX25519Key(t)
	blob, err := encrypt(t, patternBytes(9000),
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)

	// Same kid, different private key: the entry matches by kid, but the ECDH
	// agreement derives the wrong KEK and the AES-KW integrity check fails.
	wrong := newX25519Key(t)
	r, err := fee.Decrypt(bytes.NewReader(blob), fee.NewECDHESUnwrapper(ecdhKID, wrong))
	require.Nil(t, r)
	require.ErrorIs(t, err, fee.ErrNoMatchingRecipient)
	require.ErrorIs(t, err, aeskw.ErrIntegrity)
	require.NotErrorIs(t, err, aesstream.ErrCorrupted, "STREAM decryption must not be attempted")
}

// TestDecryptWrongA256KWKEK confirms that when the kid matches but the KEK is
// wrong, the unwrap fails the AES-KW integrity check, so no recipient can be
// unwrapped, and no plaintext reader is produced — decryption is never reached.
func TestDecryptWrongA256KWKEK(t *testing.T) {
	blob, err := encrypt(t, patternBytes(9000),
		[]fee.Recipient{fee.NewA256KWRecipient(a256kwKID, newKEK(t))},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)

	r, err := fee.Decrypt(bytes.NewReader(blob), fee.NewA256KWUnwrapper(a256kwKID, newKEK(t)))
	require.Nil(t, r)
	require.ErrorIs(t, err, fee.ErrNoMatchingRecipient)
	require.ErrorIs(t, err, aeskw.ErrIntegrity)
	require.NotErrorIs(t, err, aesstream.ErrCorrupted, "STREAM decryption must not be attempted")
}

// TestDecryptAlgMismatch confirms a key is never tried against a recipient of
// another key-wrap algorithm. An A256KW unwrapper is pointed at an ECDH-ES
// recipient by reusing its kid, so the kids match but the algorithms do not.
func TestDecryptAlgMismatch(t *testing.T) {
	key := newX25519Key(t)
	blob, err := encrypt(t, patternBytes(5000),
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)

	// Same kid as the ECDH-ES entry, but an A256KW unwrapper.
	r, err := fee.Decrypt(bytes.NewReader(blob), fee.NewA256KWUnwrapper(ecdhKID, newKEK(t)))
	require.Nil(t, r)
	require.ErrorIs(t, err, fee.ErrNoMatchingRecipient)
	require.NotErrorIs(t, err, aeskw.ErrIntegrity)
}

// TestDecryptCorruptedProtectedHeader confirms that flipping a byte in the
// protected-header bytes makes Decrypt fail at decode (wrapping cose.ErrMalformed)
// rather than yielding a reader that decrypts to garbage.
func TestDecryptCorruptedProtectedHeader(t *testing.T) {
	key := newX25519Key(t)
	blob, err := encrypt(t, patternBytes(8000),
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)

	// Locate the protected-header bytes via a clean decode, then flip the first
	// byte (the CBOR map head) so the protected bytes are no longer a map.
	env, _, err := cose.Decode(blob, cose.WithExpectedType(fee.EnvelopeType))
	require.NoError(t, err)
	require.NotEmpty(t, env.Headers.RawProtected)
	off := bytes.Index(blob, env.Headers.RawProtected)
	require.GreaterOrEqual(t, off, 0)

	corrupted := bytes.Clone(blob)
	corrupted[off] ^= 0xFF

	r, err := fee.Decrypt(bytes.NewReader(corrupted), fee.NewECDHESUnwrapper(ecdhKID, key))
	require.Nil(t, r)
	require.ErrorIs(t, err, cose.ErrMalformed)
}

// TestDecryptTamperedCiphertext confirms that flipping a byte in the detached
// ciphertext is detected when the plaintext is read: the stream reader returns
// aesstream.ErrCorrupted.
func TestDecryptTamperedCiphertext(t *testing.T) {
	key := newX25519Key(t)
	plaintext := patternBytes(3 * aesstream.MinChunkSize)
	blob, err := encrypt(t, plaintext,
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)

	// Flip the final byte (inside the detached ciphertext, well past the
	// envelope header).
	corrupted := bytes.Clone(blob)
	corrupted[len(corrupted)-1] ^= 0xFF

	r, err := fee.Decrypt(bytes.NewReader(corrupted), fee.NewECDHESUnwrapper(ecdhKID, key))
	require.NoError(t, err, "decode + unwrap still succeed; tampering is in the body")
	_, err = io.ReadAll(r)
	require.ErrorIs(t, err, aesstream.ErrCorrupted)
}

// TestDecryptWrongEnvelopeType confirms a blob that is not a FEE envelope (wrong
// COSE typ) is refused before any key material is used.
func TestDecryptWrongEnvelopeType(t *testing.T) {
	// A well-formed COSE_Encrypt with a non-FEE typ and a single recipient.
	other := &cose.Envelope{
		Headers: cose.Headers{
			Protected: cose.Header{}.Set(cose.HeaderLabelType, "application/not-fee"),
		},
		Recipients: []*cose.Recipient{{
			Headers:    cose.Headers{Unprotected: cose.Header{}.Set(cose.HeaderLabelKID, []byte("k"))},
			Ciphertext: []byte("xxxxxxxxxxxxxxxxxxxxxxxx"),
		}},
	}
	blob, err := other.Encode()
	require.NoError(t, err)

	r, err := fee.Decrypt(bytes.NewReader(blob), fee.NewA256KWUnwrapper([]byte("k"), newKEK(t)))
	require.Nil(t, r)
	require.ErrorIs(t, err, cose.ErrUnexpectedType)
}

// TestEncryptNoRecipients confirms Encrypt rejects an empty recipient set.
func TestEncryptNoRecipients(t *testing.T) {
	_, _, err := fee.Encrypt(bytes.NewReader(patternBytes(10)), nil)
	require.ErrorIs(t, err, fee.ErrNoRecipients)
}

// TestEncryptNilRecipient confirms a nil entry in the recipient slice is an
// error rather than a panic.
func TestEncryptNilRecipient(t *testing.T) {
	_, _, err := fee.Encrypt(bytes.NewReader(patternBytes(10)), []fee.Recipient{nil})
	require.Error(t, err)
}

// TestEncryptChunkSizeOutOfRange confirms an explicit chunk size below the body
// cipher's minimum is rejected as an invalid argument — aesstream.ErrChunkSize,
// the sentinel the body cipher itself uses — not as a malformed envelope.
func TestEncryptChunkSizeOutOfRange(t *testing.T) {
	key := newX25519Key(t)
	_, _, err := fee.Encrypt(
		bytes.NewReader(patternBytes(10)),
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(aesstream.MinChunkSize-1),
	)
	require.ErrorIs(t, err, aesstream.ErrChunkSize)
	require.NotErrorIs(t, err, fee.ErrMalformedEnvelope)
}

// TestDecryptNilArgs confirms nil src or nil unwrapper are reported, not
// dereferenced.
func TestDecryptNilArgs(t *testing.T) {
	t.Run("nil unwrapper", func(t *testing.T) {
		r, err := fee.Decrypt(bytes.NewReader([]byte{0xd8, 0x60}), nil)
		require.Nil(t, r)
		require.ErrorIs(t, err, fee.ErrNilUnwrapper)
	})
	t.Run("nil source", func(t *testing.T) {
		r, err := fee.Decrypt(nil, fee.NewA256KWUnwrapper([]byte("k"), newKEK(t)))
		require.Nil(t, r)
		require.Error(t, err)
	})
}

// TestEnvelopeWireConventions decodes a produced envelope with the cose package
// directly and asserts the FEE wire conventions of FIP-1253: the protected
// header carries the envelope type, the STREAM body algorithm, the base nonce
// in the iv and the chunk size at label -1; the unprotected header is empty;
// and the recipient entry carries the expected algorithm, kid and a
// self-describing COSE_Key ephemeral key.
func TestEnvelopeWireConventions(t *testing.T) {
	key := newX25519Key(t)
	const chunk = aesstream.MinChunkSize

	blob, err := encrypt(t, patternBytes(2000),
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(chunk),
	)
	require.NoError(t, err)

	env, ciphertext, err := cose.Decode(blob, cose.WithExpectedType(fee.EnvelopeType))
	require.NoError(t, err)

	// Protected header: every FEE parameter is authenticated via the AAD.
	typ, ok := env.Headers.Protected.Text(cose.HeaderLabelType)
	require.True(t, ok)
	require.Equal(t, "application/vnd.filecoin-encryption+cose", typ)

	alg, ok := env.Headers.Protected.Int(cose.HeaderLabelAlg)
	require.True(t, ok)
	require.Equal(t, algChunkedStream, alg, "chunked AES-256-GCM-STREAM private-use alg")

	cs, ok := env.Headers.Protected.Int(labelChunkSize)
	require.True(t, ok, "chunk size recorded at protected label -1")
	require.Equal(t, int64(chunk), cs)

	iv, ok := env.Headers.Protected.Bytes(cose.HeaderLabelIV)
	require.True(t, ok, "base nonce recorded in the protected iv")
	require.Len(t, iv, aesstream.BaseNonceSize)

	require.Empty(t, env.Headers.Unprotected, "the body unprotected header is empty")

	// Recipient: algorithm, kid, and a self-describing COSE_Key ephemeral key.
	require.Len(t, env.Recipients, 1)
	rcpt := env.Recipients[0]
	ralg, ok := rcpt.Headers.Protected.Int(cose.HeaderLabelAlg)
	require.True(t, ok)
	require.Equal(t, cose.AlgECDHESA256KW, ralg)
	kid, ok := rcpt.Headers.Unprotected.Bytes(cose.HeaderLabelKID)
	require.True(t, ok)
	require.Equal(t, ecdhKID, kid)

	ephRaw, ok := rcpt.Headers.Unprotected.Get(cose.HeaderLabelEphemeralKey)
	require.True(t, ok, "ECDH-ES recipient carries an ephemeral key")
	eph, ok := ephRaw.(map[any]any)
	require.True(t, ok, "ephemeral key is a self-describing COSE_Key map")
	require.Equal(t, coseKtyOKP, eph[coseKeyKty], "kty OKP")
	require.Equal(t, coseCrvX25519, eph[coseKeyCrv], "crv X25519")
	x, ok := eph[coseKeyX].([]byte)
	require.True(t, ok, "ephemeral key x is a byte string")
	require.Len(t, x, 32, "X25519 public key is 32 bytes")

	// The detached ciphertext is non-empty and decrypts back through the API.
	require.NotEmpty(t, ciphertext)
}

// TestECDHRecipientProtectedBytes pins the recipient protected header an
// ECDH-ES+A256KW recipient puts on the wire. Those bytes are an input to the
// key derivation (RFC 9053 §5.2), so a change here changes every derived KEK
// and breaks unwrapping by any other implementation — including an earlier
// build of this one. The value is the canonical encoding of {1: -31}.
func TestECDHRecipientProtectedBytes(t *testing.T) {
	key := newX25519Key(t)

	blob, err := encrypt(t, patternBytes(64),
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())})
	require.NoError(t, err)

	env, _, err := cose.Decode(blob, cose.WithExpectedType(fee.EnvelopeType))
	require.NoError(t, err)
	require.Len(t, env.Recipients, 1)

	got, err := env.Recipients[0].Headers.ProtectedBytes()
	require.NoError(t, err, "recipient ProtectedBytes")
	require.Equal(t, []byte{0xa1, 0x01, 0x38, 0x1e}, got, "recipient protected header")
}

// TestPlaintextLengthWritten confirms the plaintext length is written to
// the protected header only when it is declared, and that the envelope
// decrypts either way.
func TestPlaintextLengthWritten(t *testing.T) {
	key := newX25519Key(t)
	const chunk = aesstream.MinChunkSize
	plaintext := patternBytes(3*chunk + 10) // 4 chunks

	t.Run("present and correct when the length is declared", func(t *testing.T) {
		blob, err := encrypt(t, plaintext,
			[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
			fee.WithChunkSize(chunk), fee.WithPlaintextLength(int64(len(plaintext))),
		)
		require.NoError(t, err)

		env, _, err := cose.Decode(blob, cose.WithExpectedType(fee.EnvelopeType))
		require.NoError(t, err)
		n, ok := env.Headers.Protected.Int(labelPlaintextLength)
		require.True(t, ok, "plaintext length present when declared")
		require.Equal(t, int64(len(plaintext)), n)

		require.Equal(t, plaintext, decryptAll(t, blob, fee.NewECDHESUnwrapper(ecdhKID, key)))
	})

	t.Run("omitted when the length is unknown", func(t *testing.T) {
		blob, err := encrypt(t, plaintext,
			[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
			fee.WithChunkSize(chunk),
		)
		require.NoError(t, err)

		env, _, err := cose.Decode(blob, cose.WithExpectedType(fee.EnvelopeType))
		require.NoError(t, err)
		require.False(t, env.Headers.Protected.Has(labelPlaintextLength),
			"plaintext length omitted when unknown")

		require.Equal(t, plaintext, decryptAll(t, blob, fee.NewECDHESUnwrapper(ecdhKID, key)))
	})
}

// TestPlaintextLengthMismatch confirms that when the declared plaintext length does
// not match the plaintext actually streamed, the returned reader surfaces
// ErrPlaintextLengthMismatch (the already-written plaintext length cannot be
// trusted).
func TestPlaintextLengthMismatch(t *testing.T) {
	key := newX25519Key(t)
	// Multiple chunks, so some full chunks are emitted before the final chunk is
	// withheld on the mismatch.
	plaintext := patternBytes(2*aesstream.MinChunkSize + 7)

	enc, _, err := fee.Encrypt(bytes.NewReader(plaintext),
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(aesstream.MinChunkSize),
		fee.WithPlaintextLength(int64(len(plaintext)+1)), // declare one byte too many
	)
	require.NoError(t, err)
	defer enc.Close()

	// The mismatch surfaces as a non-EOF error from the reader...
	blob, err := io.ReadAll(enc)
	require.ErrorIs(t, err, fee.ErrPlaintextLengthMismatch)

	// ...and because the final chunk was withheld, the bytes produced so far do
	// not decrypt cleanly: a caller that ignored the error and stored the blob
	// gets a truncated, unauthenticatable object rather than a valid-but-
	// mislabeled one. The header still decodes and the CEK still unwraps; the
	// failure is in the truncated body.
	r, derr := fee.Decrypt(bytes.NewReader(blob), fee.NewECDHESUnwrapper(ecdhKID, key))
	require.NoError(t, derr)
	_, derr = io.ReadAll(r)
	require.ErrorIs(t, derr, aesstream.ErrTruncated)
}

// TestChunkSizeIsSelfDescribing confirms an envelope sealed with a non-default
// chunk size decrypts without the caller passing that size to Decrypt — proving
// it travels in the envelope.
func TestChunkSizeIsSelfDescribing(t *testing.T) {
	key := newX25519Key(t)
	plaintext := patternBytes(5 * 8192)

	blob, err := encrypt(t, plaintext,
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(8192),
	)
	require.NoError(t, err)

	// Decrypt is given only the blob and the unwrapper; it must recover the
	// 8 KiB chunk size from the envelope to frame the ciphertext correctly.
	require.Equal(t, plaintext, decryptAll(t, blob, fee.NewECDHESUnwrapper(ecdhKID, key)))
}

// TestDecryptStreamsIncrementally confirms the returned reader is a real stream:
// reading one byte at a time reassembles the exact plaintext.
func TestDecryptStreamsIncrementally(t *testing.T) {
	key := newX25519Key(t)
	plaintext := patternBytes(2*aesstream.MinChunkSize + 13)
	blob, err := encrypt(t, plaintext,
		[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())},
		fee.WithChunkSize(aesstream.MinChunkSize),
	)
	require.NoError(t, err)

	r, err := fee.Decrypt(bytes.NewReader(blob), fee.NewECDHESUnwrapper(ecdhKID, key))
	require.NoError(t, err)

	var got bytes.Buffer
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}
	require.Equal(t, plaintext, got.Bytes())
}

// TestEncryptInvalidRecipient confirms a malformed recipient is rejected up
// front (before the plaintext is sealed), not deep inside the wrap step.
func TestEncryptInvalidRecipient(t *testing.T) {
	t.Run("ECDH-ES nil public key", func(t *testing.T) {
		_, _, err := fee.Encrypt(bytes.NewReader(patternBytes(10)),
			[]fee.Recipient{fee.NewECDHESRecipient(ecdhKID, nil)})
		require.Error(t, err)
	})
	t.Run("A256KW wrong KEK length", func(t *testing.T) {
		_, _, err := fee.Encrypt(bytes.NewReader(patternBytes(10)),
			[]fee.Recipient{fee.NewA256KWRecipient(a256kwKID, make([]byte, 16))})
		require.Error(t, err)
	})
}

// TestDecryptMalformedChunkSizeHeader confirms that a chunk-size header which is
// present but not an integer is rejected as a malformed envelope, rather than
// silently falling back to the default size. The recipient carries a real
// wrapped CEK so the unwrap succeeds and Decrypt reaches the chunk-size check.
func TestDecryptMalformedChunkSizeHeader(t *testing.T) {
	kek := newKEK(t)
	cek := newCEK(t)
	wrappedCEK, err := aeskw.Wrap(kek, cek)
	require.NoError(t, err)

	// Hand-build an envelope whose chunk-size header (FEE private-use label, in
	// the protected header) is present but holds a string instead of an integer.
	env := &cose.Envelope{
		Headers: cose.Headers{
			Protected: cose.Header{}.
				Set(cose.HeaderLabelAlg, algChunkedStream).
				Set(cose.HeaderLabelType, fee.EnvelopeType).
				Set(cose.HeaderLabelIV, make([]byte, aesstream.BaseNonceSize)).
				Set(labelChunkSize, "not-an-integer"),
			Unprotected: cose.Header{},
		},
		Recipients: []*cose.Recipient{{
			Headers: cose.Headers{
				Unprotected: cose.Header{}.
					Set(cose.HeaderLabelAlg, cose.AlgA256KW).
					Set(cose.HeaderLabelKID, a256kwKID),
			},
			Ciphertext: wrappedCEK,
		}},
	}
	blob, err := env.Encode()
	require.NoError(t, err)

	r, err := fee.Decrypt(bytes.NewReader(blob), fee.NewA256KWUnwrapper(a256kwKID, kek))
	require.Nil(t, r)
	require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
}

// TestDecryptMalformedEphemeralKey confirms an ECDH-ES recipient whose ephemeral
// key is not a valid X25519 COSE_Key is rejected as a malformed envelope, before
// any ECDH is attempted. Each case hand-builds a recipient the unwrapper matches
// by kid and algorithm, so decode + match succeed and the ephemeral-key decode
// is what fails.
func TestDecryptMalformedEphemeralKey(t *testing.T) {
	key := newX25519Key(t)
	goodX := key.PublicKey().Bytes()

	cases := []struct {
		name string
		eph  any
	}{
		{"not a COSE_Key map", []byte("raw-ephemeral-bytes-not-a-map!!!")},
		{"wrong key type", map[any]any{coseKeyKty: int64(2), coseKeyCrv: coseCrvX25519, coseKeyX: goodX}},
		{"wrong curve", map[any]any{coseKeyKty: coseKtyOKP, coseKeyCrv: int64(6), coseKeyX: goodX}},
		{"missing x coordinate", map[any]any{coseKeyKty: coseKtyOKP, coseKeyCrv: coseCrvX25519}},
		{"x not a byte string", map[any]any{coseKeyKty: coseKtyOKP, coseKeyCrv: coseCrvX25519, coseKeyX: int64(7)}},
		{"x wrong length", map[any]any{coseKeyKty: coseKtyOKP, coseKeyCrv: coseCrvX25519, coseKeyX: []byte("short")}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env := &cose.Envelope{
				Headers: cose.Headers{
					Protected: cose.Header{}.
						Set(cose.HeaderLabelAlg, algChunkedStream).
						Set(cose.HeaderLabelType, fee.EnvelopeType).
						Set(cose.HeaderLabelIV, make([]byte, aesstream.BaseNonceSize)).
						Set(labelChunkSize, int64(aesstream.MinChunkSize)),
					Unprotected: cose.Header{},
				},
				Recipients: []*cose.Recipient{{
					Headers: cose.Headers{
						Protected: cose.Header{}.Set(cose.HeaderLabelAlg, cose.AlgECDHESA256KW),
						Unprotected: cose.Header{}.
							Set(cose.HeaderLabelKID, ecdhKID).
							Set(cose.HeaderLabelEphemeralKey, tc.eph),
					},
					Ciphertext: make([]byte, 40), // arbitrary; the unwrap is never reached
				}},
			}
			blob, err := env.Encode()
			require.NoError(t, err)

			r, err := fee.Decrypt(bytes.NewReader(blob), fee.NewECDHESUnwrapper(ecdhKID, key))
			require.Nil(t, r)
			require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
		})
	}
}

// name renders a byte count for a subtest name.
func name(n int) string {
	if n == 0 {
		return "empty"
	}
	return "n=" + strconv.Itoa(n)
}

// TestA256KWRecipientWire pins the A256KW recipient layout RFC 9053 §6.2.1
// requires: an empty protected header, encoded as a zero-length byte string,
// with the algorithm in the unprotected header beside the kid.
func TestA256KWRecipientWire(t *testing.T) {
	kek := newKEK(t)
	blob, err := encrypt(t, patternBytes(100), []fee.Recipient{fee.NewA256KWRecipient(a256kwKID, kek)})
	require.NoError(t, err)

	env, _, err := cose.Decode(blob)
	require.NoError(t, err)
	require.Len(t, env.Recipients, 1)
	rcpt := env.Recipients[0]

	prot, err := rcpt.Headers.ProtectedBytes()
	require.NoError(t, err)
	require.Empty(t, prot, "protected header is a zero-length byte string")
	alg, ok := rcpt.Headers.Unprotected.Int(cose.HeaderLabelAlg)
	require.True(t, ok)
	require.Equal(t, cose.AlgA256KW, alg)

	require.Equal(t, patternBytes(100), decryptAll(t, blob, fee.NewA256KWUnwrapper(a256kwKID, kek)))
}

// TestA256KWRecipientProtectedAlgRejected: an A256KW recipient whose algorithm
// sits in a non-empty protected header breaks RFC 9053 §6.2.1 and is rejected
// as malformed rather than unwrapped.
func TestA256KWRecipientProtectedAlgRejected(t *testing.T) {
	kek := newKEK(t)
	blob, err := encrypt(t, patternBytes(100), []fee.Recipient{fee.NewA256KWRecipient(a256kwKID, kek)})
	require.NoError(t, err)

	env, ciphertext, err := cose.Decode(blob)
	require.NoError(t, err)
	rcpt := env.Recipients[0]
	rcpt.Headers.Unprotected = cose.Header{}.Set(cose.HeaderLabelKID, a256kwKID)
	rcpt.Headers.Protected = cose.Header{}.Set(cose.HeaderLabelAlg, cose.AlgA256KW)
	rcpt.Headers.RawProtected = nil
	header, err := env.Encode()
	require.NoError(t, err)

	r, err := fee.Decrypt(bytes.NewReader(append(header, ciphertext...)), fee.NewA256KWUnwrapper(a256kwKID, kek))
	require.Nil(t, r)
	require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
}

// sealEnvelope seals plaintext under cek behind a hand-built body header, with
// the envelope's own Enc_structure as AAD, so a test can exercise a header the
// encoder never writes.
func sealEnvelope(t *testing.T, protected cose.Header, plaintext, cek []byte) []byte {
	t.Helper()
	env := &cose.Envelope{Headers: cose.Headers{Protected: protected, Unprotected: cose.Header{}}}
	aad, err := env.EncStructure(nil)
	require.NoError(t, err)
	header, err := env.Encode()
	require.NoError(t, err)
	baseNonce, ok := protected.Bytes(cose.HeaderLabelIV)
	require.True(t, ok)
	chunkSize, ok := protected.Int(labelChunkSize)
	require.True(t, ok)
	body, err := aesstream.Seal(aesstream.Config{Key: cek, BaseNonce: baseNonce, AAD: aad, ChunkSize: int(chunkSize)}, plaintext)
	require.NoError(t, err)
	return append(header, body...)
}

// bodyHeader is a valid FEE body protected header for a test to adjust.
func bodyHeader() cose.Header {
	return cose.Header{}.
		Set(cose.HeaderLabelAlg, algChunkedStream).
		Set(cose.HeaderLabelType, fee.EnvelopeType).
		Set(cose.HeaderLabelIV, bytes.Repeat([]byte{0x5a}, aesstream.BaseNonceSize)).
		Set(labelChunkSize, int64(aesstream.MinChunkSize))
}

// TestDecryptIgnoresProtectedAppMetadata: application metadata in the
// protected header is authenticated with the rest of it and otherwise ignored.
func TestDecryptIgnoresProtectedAppMetadata(t *testing.T) {
	cek, plaintext := newCEK(t), patternBytes(3*aesstream.MinChunkSize+7)
	blob := sealEnvelope(t, bodyHeader().Set(labelAppMetadata, map[string]any{"cid": []byte{0x01, 0x55}}), plaintext, cek)

	r, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// TestDecryptRequiresChunkSize: the chunk size is required, so an envelope
// without one is malformed rather than read at a default size.
func TestDecryptRequiresChunkSize(t *testing.T) {
	cek := newCEK(t)
	h := bodyHeader()
	blob := sealEnvelope(t, h, patternBytes(100), cek)
	env, ciphertext, err := cose.Decode(blob)
	require.NoError(t, err)
	delete(env.Headers.Protected, labelChunkSize)
	env.Headers.RawProtected = nil
	header, err := env.Encode()
	require.NoError(t, err)

	_, err = fee.DecryptWithCEK(bytes.NewReader(append(header, ciphertext...)), cek)
	require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
}

// TestDecryptDeclaredLengthMismatch: an envelope whose authenticated plaintext
// length disagrees with its ciphertext (only a faulty encoder can produce one)
// is refused the same way by the whole-object and range paths.
func TestDecryptDeclaredLengthMismatch(t *testing.T) {
	cek, plaintext := newCEK(t), patternBytes(2*aesstream.MinChunkSize+7)
	blob := sealEnvelope(t, bodyHeader().Set(labelPlaintextLength, int64(len(plaintext)+1)), plaintext, cek)

	r, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
	require.NoError(t, err)
	_, err = io.ReadAll(r)
	require.ErrorIs(t, err, fee.ErrSizeMismatch)

	_, err = fee.PlaintextSize(bytes.NewReader(blob), int64(len(blob)))
	require.ErrorIs(t, err, fee.ErrSizeMismatch)
}

// TestDecryptCrit: crit must be protected, must be a non-empty array, and may
// name only body parameters this package processes.
func TestDecryptCrit(t *testing.T) {
	cek, plaintext := newCEK(t), patternBytes(aesstream.MinChunkSize+9)

	t.Run("naming understood parameters decrypts", func(t *testing.T) {
		blob := sealEnvelope(t, bodyHeader().Set(cose.HeaderLabelCrit, []any{labelChunkSize, cose.HeaderLabelIV}), plaintext, cek)
		r, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
	})

	for name, protected := range map[string]cose.Header{
		"naming an unknown parameter": bodyHeader().Set(cose.HeaderLabelCrit, []any{int64(-70000)}),
		"naming a text label":         bodyHeader().Set(cose.HeaderLabelCrit, []any{"x"}),
		"naming crit itself":          bodyHeader().Set(cose.HeaderLabelCrit, []any{cose.HeaderLabelCrit}),
		"naming an absent parameter":  bodyHeader().Set(cose.HeaderLabelCrit, []any{labelPlaintextLength}),
		"empty":                       bodyHeader().Set(cose.HeaderLabelCrit, []any{}),
		"not an array":                bodyHeader().Set(cose.HeaderLabelCrit, int64(5)),
	} {
		t.Run(name, func(t *testing.T) {
			blob := sealEnvelope(t, protected, plaintext, cek)
			_, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
			require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
		})
	}

	t.Run("unprotected", func(t *testing.T) {
		blob := sealEnvelope(t, bodyHeader(), plaintext, cek)
		moved := withUnprotected(t, blob, cose.HeaderLabelCrit, []any{labelChunkSize})
		_, err := fee.DecryptWithCEK(bytes.NewReader(moved), cek)
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
	})
}

// TestDecryptRejectsPartialIV: the nonce comes from the iv alone, so a Partial
// IV in either bucket is refused rather than ignored.
func TestDecryptRejectsPartialIV(t *testing.T) {
	cek, plaintext := newCEK(t), patternBytes(100)

	blob := sealEnvelope(t, bodyHeader().Set(cose.HeaderLabelPartialIV, []byte{1}), plaintext, cek)
	_, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
	require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "protected")

	moved := withUnprotected(t, sealEnvelope(t, bodyHeader(), plaintext, cek), cose.HeaderLabelPartialIV, []byte{1})
	_, err = fee.DecryptWithCEK(bytes.NewReader(moved), cek)
	require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "unprotected")
}

// TestDecryptRequiresStrictEncoding: envelopes are decoded under the strict
// CBOR profile, so a float anywhere, even in an otherwise ignored unprotected
// parameter, is refused.
func TestDecryptRequiresStrictEncoding(t *testing.T) {
	cek := newCEK(t)
	blob := withUnprotected(t, sealEnvelope(t, bodyHeader(), patternBytes(100), cek), int64(99), 1.5)

	_, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
	require.ErrorIs(t, err, cose.ErrMalformed)
	_, err = fee.PlaintextSize(bytes.NewReader(blob), int64(len(blob)))
	require.ErrorIs(t, err, cose.ErrMalformed)
}

// TestRecipientCrit: a recipient's crit is processed before its unwrap, and
// naming a parameter the unwrapper does not understand is malformed.
func TestRecipientCrit(t *testing.T) {
	key := newX25519Key(t)
	blob, err := encrypt(t, patternBytes(100), []fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())})
	require.NoError(t, err)

	for name, mutate := range map[string]func(*cose.Recipient){
		"naming an unknown parameter": func(r *cose.Recipient) {
			r.Headers.Protected.Set(cose.HeaderLabelCrit, []any{int64(-70000)})
			r.Headers.RawProtected = nil
		},
		"unprotected": func(r *cose.Recipient) {
			r.Headers.Unprotected.Set(cose.HeaderLabelCrit, []any{cose.HeaderLabelKID})
		},
		"naming the ephemeral key": func(r *cose.Recipient) {
			r.Headers.Protected.Set(cose.HeaderLabelCrit, []any{cose.HeaderLabelEphemeralKey})
			r.Headers.RawProtected = nil
		},
		"naming a kid the protected header does not carry": func(r *cose.Recipient) {
			r.Headers.Protected.Set(cose.HeaderLabelCrit, []any{cose.HeaderLabelKID})
			r.Headers.RawProtected = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			env, ciphertext, err := cose.Decode(blob)
			require.NoError(t, err)
			mutate(env.Recipients[0])
			header, err := env.Encode()
			require.NoError(t, err)

			_, err = fee.Decrypt(bytes.NewReader(append(header, ciphertext...)), fee.NewECDHESUnwrapper(ecdhKID, key))
			require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
		})
	}
}

// withUnprotected re-encodes blob with label set to value in its body
// unprotected header, leaving the protected header and ciphertext alone.
func withUnprotected(t *testing.T, blob []byte, label, value any) []byte {
	t.Helper()
	env, ciphertext, err := cose.Decode(blob)
	require.NoError(t, err)
	env.Headers.Unprotected.Set(label, value)
	header, err := env.Encode()
	require.NoError(t, err)
	return append(header, ciphertext...)
}

// TestDecryptReaderCloses: the plaintext reader closes whether or not the
// envelope declares a plaintext length, so a caller abandoning a partial read
// still returns its chunk buffers.
func TestDecryptReaderCloses(t *testing.T) {
	cek, plaintext := newCEK(t), patternBytes(3*aesstream.MinChunkSize)
	for name, opts := range map[string][]fee.EncryptOption{
		"declared length": {fee.WithChunkSize(aesstream.MinChunkSize), fee.WithPlaintextLength(int64(len(plaintext)))},
		"no length":       {fee.WithChunkSize(aesstream.MinChunkSize)},
	} {
		t.Run(name, func(t *testing.T) {
			rc, _, err := fee.EncryptWithCEK(bytes.NewReader(plaintext), cek, nil, opts...)
			require.NoError(t, err)
			blob, err := io.ReadAll(rc)
			require.NoError(t, err)
			require.NoError(t, rc.Close())

			r, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
			require.NoError(t, err)
			_, err = io.ReadFull(r, make([]byte, 10))
			require.NoError(t, err)

			c, ok := r.(io.Closer)
			require.True(t, ok, "the plaintext reader implements io.Closer")
			require.NoError(t, c.Close())
			_, err = r.Read(make([]byte, 10))
			require.Error(t, err, "reads after Close fail")
		})
	}
}

// TestECDHESRecipientUnprotectedAlgRejected: an ECDH-ES recipient's protected
// header feeds its key derivation and is fixed at {1: -31}, so one whose alg
// is unprotected is malformed rather than unwrapped.
func TestECDHESRecipientUnprotectedAlgRejected(t *testing.T) {
	key := newX25519Key(t)
	blob, err := encrypt(t, patternBytes(100), []fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())})
	require.NoError(t, err)

	env, ciphertext, err := cose.Decode(blob)
	require.NoError(t, err)
	r := env.Recipients[0]
	r.Headers.Unprotected.Set(cose.HeaderLabelAlg, cose.AlgECDHESA256KW)
	r.Headers.Protected = cose.Header{}
	r.Headers.RawProtected = nil
	header, err := env.Encode()
	require.NoError(t, err)

	_, err = fee.Decrypt(bytes.NewReader(append(header, ciphertext...)), fee.NewECDHESUnwrapper(ecdhKID, key))
	require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
}

// TestDecryptRejectsMalformedAppMetadata: app_metadata must be a map with
// text-string keys.
func TestDecryptRejectsMalformedAppMetadata(t *testing.T) {
	cek, plaintext := newCEK(t), patternBytes(100)
	for name, value := range map[string]any{
		"not a map":   int64(7),
		"integer key": map[any]any{"ok": "x", int64(1): "y"},
		"boolean key": map[any]any{"ok": "x", true: "y"},
	} {
		t.Run(name, func(t *testing.T) {
			blob := sealEnvelope(t, bodyHeader().Set(labelAppMetadata, value), plaintext, cek)
			_, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
			require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
		})
	}
}

// TestDecryptContentType: content_type must be a text string or a
// non-negative integer, and an envelope may mark a present one critical.
func TestDecryptContentType(t *testing.T) {
	cek, plaintext := newCEK(t), patternBytes(100)

	for name, protected := range map[string]cose.Header{
		"text":                  bodyHeader().Set(cose.HeaderLabelContentType, "application/pdf"),
		"integer":               bodyHeader().Set(cose.HeaderLabelContentType, int64(50)),
		"text, marked critical": bodyHeader().Set(cose.HeaderLabelContentType, "text/plain").Set(cose.HeaderLabelCrit, []any{cose.HeaderLabelContentType}),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := fee.DecryptWithCEK(bytes.NewReader(sealEnvelope(t, protected, plaintext, cek)), cek)
			require.NoError(t, err)
			got, err := io.ReadAll(r)
			require.NoError(t, err)
			require.Equal(t, plaintext, got)
		})
	}

	for name, value := range map[string]any{
		"negative integer": int64(-1),
		"byte string":      []byte("text/plain"),
		"boolean":          true,
	} {
		t.Run(name, func(t *testing.T) {
			blob := sealEnvelope(t, bodyHeader().Set(cose.HeaderLabelContentType, value), plaintext, cek)
			_, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
			require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
		})
	}
}

// TestBaseNonceLength: an iv that is not a 7-byte base nonce is malformed on
// every path, including the header-only PlaintextSize, which builds no cipher.
func TestBaseNonceLength(t *testing.T) {
	cek := newCEK(t)
	for _, n := range []int{aesstream.BaseNonceSize - 1, aesstream.BaseNonceSize + 1} {
		env := &cose.Envelope{Headers: cose.Headers{
			Protected:   bodyHeader().Set(cose.HeaderLabelIV, bytes.Repeat([]byte{0x5a}, n)),
			Unprotected: cose.Header{},
		}}
		header, err := env.Encode()
		require.NoError(t, err)
		blob := append(header, make([]byte, 100+aesstream.TagSize)...)

		_, err = fee.PlaintextSize(bytes.NewReader(blob), int64(len(blob)))
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "PlaintextSize, %d-byte iv", n)
		_, err = fee.DecryptWithCEK(bytes.NewReader(blob), cek)
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "DecryptWithCEK, %d-byte iv", n)
	}
}

// TestAllZeroCEKRejected: an all-zero CEK is refused wherever one enters,
// including when a recipient unwraps to one.
func TestAllZeroCEKRejected(t *testing.T) {
	zeroCEK := make([]byte, aesstream.KeySize)

	_, _, err := fee.EncryptWithCEK(bytes.NewReader(patternBytes(100)), zeroCEK, nil)
	require.ErrorIs(t, err, fee.ErrInvalidCEK, "EncryptWithCEK")

	kek := newKEK(t)
	blob, err := encrypt(t, patternBytes(100), []fee.Recipient{fee.NewA256KWRecipient(a256kwKID, kek)})
	require.NoError(t, err)
	_, err = fee.DecryptWithCEK(bytes.NewReader(blob), zeroCEK)
	require.ErrorIs(t, err, fee.ErrInvalidCEK, "DecryptWithCEK")
	_, err = fee.DecryptRangeWithCEK(bytes.NewReader(blob), int64(len(blob)), zeroCEK, 0, 9, nil)
	require.ErrorIs(t, err, fee.ErrInvalidCEK, "DecryptRangeWithCEK")

	// A recipient whose wrapped key unwraps to all zeros.
	env, ciphertext, err := cose.Decode(blob)
	require.NoError(t, err)
	env.Recipients[0].Ciphertext, err = aeskw.Wrap(kek, zeroCEK)
	require.NoError(t, err)
	header, err := env.Encode()
	require.NoError(t, err)
	forged := append(header, ciphertext...)

	_, err = fee.Decrypt(bytes.NewReader(forged), fee.NewA256KWUnwrapper(a256kwKID, kek))
	require.ErrorIs(t, err, fee.ErrInvalidCEK, "Decrypt")
	_, err = fee.DecryptRange(bytes.NewReader(forged), int64(len(forged)), fee.NewA256KWUnwrapper(a256kwKID, kek), 0, 9)
	require.ErrorIs(t, err, fee.ErrInvalidCEK, "DecryptRange")
}

// TestAppMetadataNesting: application metadata may nest up to 256 levels
// deep, the TypeScript implementation's limit, and no deeper.
func TestAppMetadataNesting(t *testing.T) {
	cek, plaintext := newCEK(t), patternBytes(100)
	nested := func(depth int) any {
		var v any = int64(1)
		for range depth {
			v = []any{v}
		}
		return v
	}

	blob := sealEnvelope(t, bodyHeader().Set(labelAppMetadata, map[any]any{"x": nested(200)}), plaintext, cek)
	r, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
	require.NoError(t, err, "200 levels decode")
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)

	blob = sealEnvelope(t, bodyHeader().Set(labelAppMetadata, map[any]any{"x": nested(300)}), plaintext, cek)
	_, err = fee.DecryptWithCEK(bytes.NewReader(blob), cek)
	require.ErrorIs(t, err, cose.ErrMalformed, "300 levels are refused")
}

// TestDecryptRejectsBodyLabelOverlap: no label may appear in both the body's
// protected and unprotected headers, including ones FEE does not define.
func TestDecryptRejectsBodyLabelOverlap(t *testing.T) {
	cek, plaintext := newCEK(t), patternBytes(100)
	for name, label := range map[string]any{
		"content_type":  cose.HeaderLabelContentType,
		"unknown label": int64(99),
	} {
		t.Run(name, func(t *testing.T) {
			blob := sealEnvelope(t, bodyHeader().Set(label, "x"), plaintext, cek)
			blob = withUnprotected(t, blob, label, "y")
			_, err := fee.DecryptWithCEK(bytes.NewReader(blob), cek)
			require.ErrorIs(t, err, fee.ErrMalformedEnvelope)
		})
	}
}

// TestDecryptValidatesEveryRecipient: a malformed recipient fails the whole
// envelope on every path, even when the recipient the caller uses is sound and
// even when no recipient is used at all.
func TestDecryptValidatesEveryRecipient(t *testing.T) {
	kek1, kek2 := newKEK(t), newKEK(t)
	ephX := newX25519Key(t).PublicKey().Bytes()
	cek := newCEK(t)
	rc, _, err := fee.EncryptWithCEK(bytes.NewReader(patternBytes(100)), cek, []fee.Recipient{
		fee.NewA256KWRecipient([]byte("kek-1"), kek1),
		fee.NewA256KWRecipient([]byte("kek-2"), kek2),
	})
	require.NoError(t, err)
	blob, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	for name, mutate := range map[string]func(*cose.Recipient){
		"short A256KW wrapped key": func(r *cose.Recipient) { r.Ciphertext = r.Ciphertext[:39] },
		"no algorithm":             func(r *cose.Recipient) { delete(r.Headers.Unprotected, cose.HeaderLabelAlg) },
		"kid not a byte string":    func(r *cose.Recipient) { r.Headers.Unprotected.Set(cose.HeaderLabelKID, "kek-2") },
		"ECDH-ES recipient without an ephemeral key": func(r *cose.Recipient) {
			delete(r.Headers.Unprotected, cose.HeaderLabelAlg)
			r.Headers.Protected = cose.Header{}.Set(cose.HeaderLabelAlg, cose.AlgECDHESA256KW)
			r.Headers.RawProtected = nil
		},
		"null ciphertext, unknown algorithm": func(r *cose.Recipient) {
			r.Headers.Unprotected.Set(cose.HeaderLabelAlg, int64(-65536))
			r.Ciphertext = nil
		},
		"short ECDH-ES+A256KW wrapped key": func(r *cose.Recipient) {
			delete(r.Headers.Unprotected, cose.HeaderLabelAlg)
			r.Headers.Protected = cose.Header{}.Set(cose.HeaderLabelAlg, cose.AlgECDHESA256KW)
			r.Headers.RawProtected = nil
			r.Headers.Unprotected.Set(cose.HeaderLabelEphemeralKey, map[any]any{
				coseKeyKty: coseKtyOKP, coseKeyCrv: coseCrvX25519, coseKeyX: ephX,
			})
			r.Ciphertext = r.Ciphertext[:39]
		},
		"kid in both buckets": func(r *cose.Recipient) {
			// A256KW must keep its protected header empty, so this second
			// recipient becomes an unknown algorithm to carry a protected kid.
			r.Headers.Unprotected.Set(cose.HeaderLabelAlg, int64(-65536))
			r.Headers.Protected = cose.Header{}.Set(cose.HeaderLabelKID, []byte("kek-2"))
			r.Headers.RawProtected = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			env, ciphertext, err := cose.Decode(blob)
			require.NoError(t, err)
			mutate(env.Recipients[1])
			header, err := env.Encode()
			require.NoError(t, err)
			bad := append(header, ciphertext...)

			_, err = fee.Decrypt(bytes.NewReader(bad), fee.NewA256KWUnwrapper([]byte("kek-1"), kek1))
			require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "Decrypt with the sound recipient")
			_, err = fee.DecryptWithCEK(bytes.NewReader(bad), cek)
			require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "DecryptWithCEK")
			_, err = fee.PlaintextSize(bytes.NewReader(bad), int64(len(bad)))
			require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "PlaintextSize")
		})
	}
}

// TestDecryptMatchesProtectedKID: a recipient's kid is read from the protected
// header as well as the unprotected one. The ECDH-ES recipient here was wrapped
// with its kid protected, since the protected header feeds the key derivation.
func TestDecryptMatchesProtectedKID(t *testing.T) {
	key := newX25519Key(t)
	cek, plaintext := newCEK(t), patternBytes(100)
	rc, _, err := fee.EncryptWithCEK(bytes.NewReader(plaintext), cek, []fee.Recipient{fee.NewECDHESRecipient(ecdhKID, key.PublicKey())})
	require.NoError(t, err)
	blob, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	protected := cose.Header{}.Set(cose.HeaderLabelAlg, cose.AlgECDHESA256KW).Set(cose.HeaderLabelKID, ecdhKID)
	protectedBytes, err := cose.Headers{Protected: protected}.ProtectedBytes()
	require.NoError(t, err)
	w, err := ecdhkw.Wrap(key.PublicKey(), cek, protectedBytes)
	require.NoError(t, err)

	env, ciphertext, err := cose.Decode(blob)
	require.NoError(t, err)
	env.Recipients[0] = &cose.Recipient{
		Headers: cose.Headers{
			Protected: protected,
			Unprotected: cose.Header{}.Set(cose.HeaderLabelEphemeralKey, map[any]any{
				coseKeyKty: coseKtyOKP, coseKeyCrv: coseCrvX25519, coseKeyX: w.EphemeralPublicKey.Bytes(),
			}),
		},
		Ciphertext: w.WrappedCEK,
	}
	header, err := env.Encode()
	require.NoError(t, err)

	require.Equal(t, plaintext, decryptAll(t, append(header, ciphertext...), fee.NewECDHESUnwrapper(ecdhKID, key)))
}

// TestKidlessRecipients: a recipient written without a kid leaves the label
// out, and is unwrapped by trying keys: a key with a kid and a key without one
// both recover it, through Decrypt and DecryptRange alike.
func TestKidlessRecipients(t *testing.T) {
	plaintext := patternBytes(3*aesstream.MinChunkSize + 7)
	priv, kek := newX25519Key(t), newKEK(t)

	for name, tc := range map[string]struct {
		recipient fee.Recipient
		keyed     fee.RecipientUnwrapper
		kidless   fee.RecipientUnwrapper
	}{
		"ECDH-ES": {fee.NewECDHESRecipient(nil, priv.PublicKey()), fee.NewECDHESUnwrapper(ecdhKID, priv), fee.NewECDHESUnwrapper(nil, priv)},
		"A256KW":  {fee.NewA256KWRecipient(nil, kek), fee.NewA256KWUnwrapper(a256kwKID, kek), fee.NewA256KWUnwrapper(nil, kek)},
	} {
		t.Run(name, func(t *testing.T) {
			blob, err := encrypt(t, plaintext, []fee.Recipient{tc.recipient}, fee.WithChunkSize(aesstream.MinChunkSize))
			require.NoError(t, err)

			env, _, err := cose.Decode(blob)
			require.NoError(t, err)
			r := env.Recipients[0].Headers
			require.False(t, r.Protected.Has(cose.HeaderLabelKID), "no protected kid")
			require.False(t, r.Unprotected.Has(cose.HeaderLabelKID), "no unprotected kid")

			for uname, u := range map[string]fee.RecipientUnwrapper{"key with a kid": tc.keyed, "key without a kid": tc.kidless} {
				require.Equal(t, plaintext, decryptAll(t, blob, u), uname)

				rr, err := fee.DecryptRange(bytes.NewReader(blob), int64(len(blob)), u, 100, 199)
				require.NoError(t, err, uname)
				got, err := io.ReadAll(rr)
				require.NoError(t, err, uname)
				require.Equal(t, plaintext[100:200], got, uname)
			}
		})
	}
}

// TestKidlessKeyTriesKeyedRecipient: a key without a kid is tried against a
// recipient that has one.
func TestKidlessKeyTriesKeyedRecipient(t *testing.T) {
	plaintext, kek := patternBytes(100), newKEK(t)
	blob, err := encrypt(t, plaintext, []fee.Recipient{fee.NewA256KWRecipient(a256kwKID, kek)})
	require.NoError(t, err)
	require.Equal(t, plaintext, decryptAll(t, blob, fee.NewA256KWUnwrapper(nil, kek)))
}

// TestDecryptTriesNextCandidate: a key that fails the integrity check is not an
// error while another candidate remains, whether the next candidate is a later
// recipient or a later key.
func TestDecryptTriesNextCandidate(t *testing.T) {
	plaintext := patternBytes(100)
	kek1, kek2 := newKEK(t), newKEK(t)

	t.Run("later recipient", func(t *testing.T) {
		blob, err := encrypt(t, plaintext, []fee.Recipient{
			fee.NewA256KWRecipient(nil, kek1),
			fee.NewA256KWRecipient(nil, kek2),
		})
		require.NoError(t, err)
		require.Equal(t, plaintext, decryptAll(t, blob, fee.NewA256KWUnwrapper(nil, kek2)))
	})

	t.Run("later key", func(t *testing.T) {
		blob, err := encrypt(t, plaintext, []fee.Recipient{fee.NewA256KWRecipient(nil, kek2)})
		require.NoError(t, err)
		u := fee.MultiUnwrapper(fee.NewA256KWUnwrapper(nil, kek1), fee.NewA256KWUnwrapper(nil, kek2))
		require.Equal(t, plaintext, decryptAll(t, blob, u))
	})

	t.Run("matching kid first", func(t *testing.T) {
		// MaxUnwrapAttempts kid-less wrong keys come before the key whose kid
		// matches, so only trying the matching key first stays within the limit.
		blob, err := encrypt(t, plaintext, []fee.Recipient{fee.NewA256KWRecipient(a256kwKID, kek2)})
		require.NoError(t, err)
		var keys []fee.RecipientUnwrapper
		for range fee.MaxUnwrapAttempts {
			keys = append(keys, fee.NewA256KWUnwrapper(nil, newKEK(t)))
		}
		u := fee.MultiUnwrapper(append(keys, fee.NewA256KWUnwrapper(a256kwKID, kek2))...)
		require.Equal(t, plaintext, decryptAll(t, blob, u))
	})

	t.Run("mixed algorithms", func(t *testing.T) {
		priv := newX25519Key(t)
		blob, err := encrypt(t, plaintext, []fee.Recipient{
			fee.NewA256KWRecipient(nil, kek1),
			fee.NewECDHESRecipient(nil, priv.PublicKey()),
		})
		require.NoError(t, err)
		u := fee.MultiUnwrapper(fee.NewA256KWUnwrapper(nil, kek2), fee.NewECDHESUnwrapper(nil, priv))
		require.Equal(t, plaintext, decryptAll(t, blob, u))
	})
}

// TestDecryptUnwrapAttemptLimit: at most MaxUnwrapAttempts unwraps are tried.
// One wrong key against MaxUnwrapAttempts kid-less recipients fails as no
// match; one more recipient trips the limit, on both decrypt paths.
func TestDecryptUnwrapAttemptLimit(t *testing.T) {
	envelope := func(n int) []byte {
		recipients := make([]fee.Recipient, n)
		for i := range recipients {
			recipients[i] = fee.NewA256KWRecipient(nil, newKEK(t))
		}
		blob, err := encrypt(t, patternBytes(10), recipients)
		require.NoError(t, err)
		return blob
	}
	wrong := fee.NewA256KWUnwrapper(nil, newKEK(t))

	atLimit := envelope(fee.MaxUnwrapAttempts)
	_, err := fee.Decrypt(bytes.NewReader(atLimit), wrong)
	require.ErrorIs(t, err, fee.ErrNoMatchingRecipient)
	require.ErrorIs(t, err, aeskw.ErrIntegrity)

	over := envelope(fee.MaxUnwrapAttempts + 1)
	_, err = fee.Decrypt(bytes.NewReader(over), wrong)
	require.ErrorIs(t, err, fee.ErrUnwrapAttemptLimit)
	_, err = fee.DecryptRange(bytes.NewReader(over), int64(len(over)), wrong, 0, 0)
	require.ErrorIs(t, err, fee.ErrUnwrapAttemptLimit)
}

// TestMultiUnwrapperNil: a MultiUnwrapper with no keys, or with a nil entry,
// is a nil unwrapper.
func TestMultiUnwrapperNil(t *testing.T) {
	kek := newKEK(t)
	blob, err := encrypt(t, patternBytes(10), []fee.Recipient{fee.NewA256KWRecipient(a256kwKID, kek)})
	require.NoError(t, err)
	for name, u := range map[string]fee.RecipientUnwrapper{
		"empty":     fee.MultiUnwrapper(),
		"nil entry": fee.MultiUnwrapper(fee.NewA256KWUnwrapper(a256kwKID, kek), nil),
	} {
		_, err := fee.Decrypt(bytes.NewReader(blob), u)
		require.ErrorIs(t, err, fee.ErrNilUnwrapper, name)
	}
}

// zeroStream yields n zero bytes and records how many were read.
type zeroStream struct{ n, read int64 }

func (z *zeroStream) Read(p []byte) (int, error) {
	if z.read >= z.n {
		return 0, io.EOF
	}
	k := min(int64(len(p)), z.n-z.read)
	clear(p[:k])
	z.read += k
	return int(k), nil
}

// TestDecryptEnvelopeSizeLimit: an envelope declaring a 64 MiB protected
// header is refused as cose.ErrTooLarge on every decrypt path, and the
// streaming paths read no more than MaxEnvelopeSize bytes of it.
func TestDecryptEnvelopeSizeLimit(t *testing.T) {
	const declared = 64 << 20
	// 96([ h'<declared bytes>' ...
	head := []byte{0xd8, 0x60, 0x84, 0x5a, byte(declared >> 24), 0, 0, 0}

	stream := func() (io.Reader, *zeroStream) {
		z := &zeroStream{n: declared}
		return io.MultiReader(bytes.NewReader(head), z), z
	}
	r, z := stream()
	_, err := fee.Decrypt(r, fee.NewA256KWUnwrapper(a256kwKID, newKEK(t)))
	require.ErrorIs(t, err, cose.ErrTooLarge, "Decrypt")
	require.LessOrEqual(t, int64(len(head))+z.read, int64(fee.MaxEnvelopeSize), "Decrypt read")

	r, z = stream()
	_, err = fee.DecryptWithCEK(r, newCEK(t))
	require.ErrorIs(t, err, cose.ErrTooLarge, "DecryptWithCEK")
	require.LessOrEqual(t, int64(len(head))+z.read, int64(fee.MaxEnvelopeSize), "DecryptWithCEK read")

	blob := append(append([]byte{}, head...), make([]byte, 2*fee.MaxEnvelopeSize)...)
	_, err = fee.DecryptRange(bytes.NewReader(blob), int64(len(blob)), fee.NewA256KWUnwrapper(a256kwKID, newKEK(t)), 0, 0)
	require.ErrorIs(t, err, cose.ErrTooLarge, "DecryptRange")
	_, err = fee.DecryptRangeWithCEK(bytes.NewReader(blob), int64(len(blob)), newCEK(t), 0, 0, nil)
	require.ErrorIs(t, err, cose.ErrTooLarge, "DecryptRangeWithCEK")
	_, err = fee.PlaintextSize(bytes.NewReader(blob), int64(len(blob)))
	require.ErrorIs(t, err, cose.ErrTooLarge, "PlaintextSize")
}

// TestEncryptEnvelopeSizeLimit: Encrypt refuses an envelope larger than
// MaxEnvelopeSize, which no decrypt path would accept, and an envelope just
// under it round-trips on every path.
func TestEncryptEnvelopeSizeLimit(t *testing.T) {
	kek := newKEK(t)
	// A distinct 1000-byte kid per recipient, so each encodes to 1051 bytes.
	kid := func(i int) []byte {
		k := make([]byte, 1000)
		k[0], k[1] = byte(i>>8), byte(i)
		return k
	}
	recipients := func(n int) []fee.Recipient {
		rs := make([]fee.Recipient, n)
		for i := range rs {
			rs[i] = fee.NewA256KWRecipient(kid(i), kek)
		}
		return rs
	}

	_, _, err := fee.Encrypt(bytes.NewReader(patternBytes(10)), recipients(1000))
	require.ErrorIs(t, err, cose.ErrTooLarge)

	plaintext := patternBytes(100)
	blob, err := encrypt(t, plaintext, recipients(990))
	require.NoError(t, err)
	env, _, err := cose.Decode(blob)
	require.NoError(t, err)
	header, err := env.Encode()
	require.NoError(t, err)
	require.Greater(t, len(header), fee.MaxEnvelopeSize-16<<10, "the envelope is close to the limit")

	u := fee.NewA256KWUnwrapper(kid(989), kek)
	require.Equal(t, plaintext, decryptAll(t, blob, u))
	rr, err := fee.DecryptRange(bytes.NewReader(blob), int64(len(blob)), u, 0, 9)
	require.NoError(t, err)
	got, err := io.ReadAll(rr)
	require.NoError(t, err)
	require.Equal(t, plaintext[:10], got)
}

// TestContentTypeEitherBucket: content_type may be unprotected, and is held to
// the same type rules there: a text string or non-negative integer decrypts,
// anything else is malformed on every path.
func TestContentTypeEitherBucket(t *testing.T) {
	cek, plaintext := newCEK(t), patternBytes(100)
	rc, _, err := fee.EncryptWithCEK(bytes.NewReader(plaintext), cek, nil)
	require.NoError(t, err)
	blob, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	withContentType := func(v any) []byte {
		env, ciphertext, err := cose.Decode(blob)
		require.NoError(t, err)
		env.Headers.Unprotected.Set(cose.HeaderLabelContentType, v)
		header, err := env.Encode()
		require.NoError(t, err)
		return append(header, ciphertext...)
	}

	for name, v := range map[string]any{"text": "application/pdf", "integer": int64(50)} {
		r, err := fee.DecryptWithCEK(bytes.NewReader(withContentType(v)), cek)
		require.NoError(t, err, name)
		got, err := io.ReadAll(r)
		require.NoError(t, err, name)
		require.Equal(t, plaintext, got, name)
	}

	for name, v := range map[string]any{"negative integer": int64(-1), "byte string": []byte("application/pdf")} {
		bad := withContentType(v)
		_, err := fee.DecryptWithCEK(bytes.NewReader(bad), cek)
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "DecryptWithCEK, %s", name)
		_, err = fee.PlaintextSize(bytes.NewReader(bad), int64(len(bad)))
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "PlaintextSize, %s", name)
		_, err = fee.DecryptRangeWithCEK(bytes.NewReader(bad), int64(len(bad)), cek, 0, 0, nil)
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "DecryptRangeWithCEK, %s", name)
	}
}

// TestPlaintextLengthSafeIntegerBound: a declared plaintext length above
// MaxPlaintextLength (2^53 - 1, which the Synapse SDK rejects) is malformed on
// every decode path, MaxPlaintextLength itself gets as far as the size check,
// and WithPlaintextLength refuses to write a larger one.
func TestPlaintextLengthSafeIntegerBound(t *testing.T) {
	cek := newCEK(t)
	rc, _, err := fee.EncryptWithCEK(bytes.NewReader(patternBytes(100)), cek, nil, fee.WithPlaintextLength(100))
	require.NoError(t, err)
	blob, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	withLength := func(n int64) []byte {
		env, ciphertext, err := cose.Decode(blob)
		require.NoError(t, err)
		env.Headers.Protected.Set(labelPlaintextLength, n)
		env.Headers.RawProtected = nil
		header, err := env.Encode()
		require.NoError(t, err)
		return append(header, ciphertext...)
	}

	over := withLength(fee.MaxPlaintextLength + 1)
	_, err = fee.DecryptWithCEK(bytes.NewReader(over), cek)
	require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "DecryptWithCEK")
	_, err = fee.PlaintextSize(bytes.NewReader(over), int64(len(over)))
	require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "PlaintextSize")
	_, err = fee.DecryptRangeWithCEK(bytes.NewReader(over), int64(len(over)), cek, 0, 0, nil)
	require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "DecryptRangeWithCEK")

	atMax := withLength(fee.MaxPlaintextLength)
	_, err = fee.PlaintextSize(bytes.NewReader(atMax), int64(len(atMax)))
	require.ErrorIs(t, err, fee.ErrSizeMismatch, "the bound itself is a valid length")

	_, _, err = fee.EncryptWithCEK(bytes.NewReader(nil), cek, nil, fee.WithPlaintextLength(fee.MaxPlaintextLength+1))
	require.Error(t, err, "WithPlaintextLength over the bound")
	rc, _, err = fee.EncryptWithCEK(bytes.NewReader(nil), cek, nil, fee.WithPlaintextLength(fee.MaxPlaintextLength))
	require.NoError(t, err, "WithPlaintextLength at the bound")
	require.NoError(t, rc.Close())
}

// TestEnvelopeErrorClassification: an envelope whose bytes are not a valid FEE
// envelope is ErrMalformedEnvelope on every path, alongside the cose sentinel,
// while a source that fails partway through the envelope keeps its own error
// and is not reported as malformed.
func TestEnvelopeErrorClassification(t *testing.T) {
	cek := newCEK(t)
	rc, _, err := fee.EncryptWithCEK(bytes.NewReader(patternBytes(100)), cek, []fee.Recipient{fee.NewA256KWRecipient(a256kwKID, newKEK(t))})
	require.NoError(t, err)
	blob, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	env, ciphertext, err := cose.Decode(blob)
	require.NoError(t, err)
	env.Headers.Protected.Set(cose.HeaderLabelType, "application/cose")
	env.Headers.RawProtected = nil
	header, err := env.Encode()
	require.NoError(t, err)
	wrongTyp := append(header, ciphertext...)

	for name, tc := range map[string]struct {
		blob []byte
		also error
	}{
		"not CBOR":           {[]byte{0xff, 0xff, 0xff}, cose.ErrMalformed},
		"not a COSE_Encrypt": {[]byte{0x01}, cose.ErrNotEncrypt},
		"wrong typ":          {wrongTyp, cose.ErrUnexpectedType},
		"oversized":          {append([]byte{0xd8, 0x60, 0x84, 0x5a, 0x01, 0, 0, 0}, make([]byte, fee.MaxEnvelopeSize)...), cose.ErrTooLarge},
	} {
		u := fee.NewA256KWUnwrapper(a256kwKID, newKEK(t))
		_, err := fee.Decrypt(bytes.NewReader(tc.blob), u)
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "Decrypt, %s", name)
		require.ErrorIs(t, err, tc.also, "Decrypt, %s", name)
		_, err = fee.DecryptWithCEK(bytes.NewReader(tc.blob), cek)
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "DecryptWithCEK, %s", name)
		_, err = fee.DecryptRange(bytes.NewReader(tc.blob), int64(len(tc.blob)), u, 0, 0)
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "DecryptRange, %s", name)
		_, err = fee.PlaintextSize(bytes.NewReader(tc.blob), int64(len(tc.blob)))
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "PlaintextSize, %s", name)
	}

	boom := errors.New("connection reset")
	failing := func() io.Reader { return io.MultiReader(bytes.NewReader(blob[:20]), iotest.ErrReader(boom)) }
	_, err = fee.Decrypt(failing(), fee.NewA256KWUnwrapper(a256kwKID, newKEK(t)))
	require.ErrorIs(t, err, boom, "Decrypt")
	require.NotErrorIs(t, err, fee.ErrMalformedEnvelope, "Decrypt")
	_, err = fee.DecryptWithCEK(failing(), cek)
	require.ErrorIs(t, err, boom, "DecryptWithCEK")
	require.NotErrorIs(t, err, fee.ErrMalformedEnvelope, "DecryptWithCEK")
}

// TestSafeIntegersOnly: an integer outside ±(2^53 - 1) anywhere in the
// envelope's headers is malformed, as the Synapse SDK requires, wherever it
// sits; integers at the bound are accepted.
func TestSafeIntegersOnly(t *testing.T) {
	const maxSafe = int64(1)<<53 - 1
	cek := newCEK(t)
	rc, _, err := fee.EncryptWithCEK(bytes.NewReader(patternBytes(100)), cek, []fee.Recipient{fee.NewA256KWRecipient(a256kwKID, newKEK(t))})
	require.NoError(t, err)
	blob, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	edited := func(edit func(*cose.Envelope)) []byte {
		env, ciphertext, err := cose.Decode(blob)
		require.NoError(t, err)
		edit(env)
		header, err := env.Encode()
		require.NoError(t, err)
		return append(header, ciphertext...)
	}
	unprotected := func(label, v any) []byte {
		return edited(func(e *cose.Envelope) { e.Headers.Unprotected.Set(label, v) })
	}

	for name, b := range map[string][]byte{
		"unprotected value above": unprotected(int64(99), maxSafe+1),
		"unprotected value below": unprotected(int64(99), -maxSafe-1),
		"unsigned beyond int64":   unprotected(int64(99), uint64(1)<<63),
		"label above":             unprotected(maxSafe+1, int64(1)),
		"nested in an array":      unprotected(int64(99), []any{int64(1), maxSafe + 1}),
		"nested map key":          unprotected(int64(99), map[any]any{maxSafe + 1: "x"}),
		"protected app_metadata": edited(func(e *cose.Envelope) {
			e.Headers.Protected.Set(labelAppMetadata, map[any]any{"n": maxSafe + 1})
			e.Headers.RawProtected = nil
		}),
		"recipient header": edited(func(e *cose.Envelope) {
			e.Recipients[0].Headers.Unprotected.Set(int64(99), maxSafe+1)
		}),
	} {
		_, err := fee.DecryptWithCEK(bytes.NewReader(b), cek)
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "DecryptWithCEK, %s", name)
		_, err = fee.PlaintextSize(bytes.NewReader(b), int64(len(b)))
		require.ErrorIs(t, err, fee.ErrMalformedEnvelope, "PlaintextSize, %s", name)
	}

	for name, b := range map[string][]byte{
		"unprotected value at the bound": unprotected(int64(99), maxSafe),
		"negative value at the bound":    unprotected(int64(99), -maxSafe),
		"label at the bound":             unprotected(maxSafe, int64(1)),
	} {
		r, err := fee.DecryptWithCEK(bytes.NewReader(b), cek)
		require.NoError(t, err, name)
		_, err = io.ReadAll(r)
		require.NoError(t, err, name)
	}
}
