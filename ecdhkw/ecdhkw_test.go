package ecdhkw_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/filecoin-project/go-fee/aeskw"
	"github.com/filecoin-project/go-fee/ecdhkw"
	"github.com/stretchr/testify/require"
)

// testProtected is the serialized COSE_Recipient protected header FEE emits for
// an ECDH-ES+A256KW recipient: the map {1: -31}. It is an input to the key
// derivation (RFC 9053 §5.2), so wrap and unwrap must be given the same bytes.
var testProtected = []byte{0xa1, 0x01, 0x38, 0x1e}

func newRecipient(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err, "generate recipient key")
	return priv
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoErrorf(t, err, "bad hex %q", s)
	return b
}

// AC: "I can wrap a CEK to an X25519 public key and unwrap it with the
// corresponding private key, recovering the original CEK." Checked across the
// valid CEK sizes (16/24/32).
func TestWrapUnwrapRoundTrip(t *testing.T) {
	recipient := newRecipient(t)
	for _, size := range []int{16, 24, 32} {
		cek := make([]byte, size)
		_, err := rand.Read(cek)
		require.NoError(t, err, "rand cek")

		w, err := ecdhkw.Wrap(recipient.PublicKey(), cek, testProtected)
		require.NoErrorf(t, err, "Wrap(%d-byte CEK)", size)
		require.Equal(t, ecdh.X25519(), w.EphemeralPublicKey.Curve(), "ephemeral key is not X25519")
		require.Lenf(t, w.WrappedCEK, size+8, "wrapped CEK length")

		got, err := ecdhkw.Unwrap(recipient, w, testProtected)
		require.NoErrorf(t, err, "Unwrap(%d-byte CEK)", size)
		require.Equalf(t, cek, got, "round-trip mismatch for %d-byte CEK", size)
	}
}

// AC: "When I attempt to unwrap with the wrong private key, unwrap returns an
// error." The wrong key derives a different KEK, so AES-KW's integrity check
// fails; the error wraps aeskw.ErrIntegrity.
func TestUnwrapWrongPrivateKey(t *testing.T) {
	recipient := newRecipient(t)
	wrongKey := newRecipient(t)
	cek := bytes.Repeat([]byte{0x5A}, 32)

	w, err := ecdhkw.Wrap(recipient.PublicKey(), cek, testProtected)
	require.NoError(t, err, "Wrap")

	got, err := ecdhkw.Unwrap(wrongKey, w, testProtected)
	require.ErrorIs(t, err, aeskw.ErrIntegrity, "Unwrap with wrong key should wrap aeskw.ErrIntegrity")
	require.Nil(t, got)
}

// AC: "When I wrap the same CEK twice to the same public key, the two wrapped
// outputs differ — the ephemeral sender key is fresh each time." Both the
// ephemeral public key and the wrapped bytes must differ, and both copies must
// still unwrap to the original CEK.
func TestWrapFreshEphemeralPerCall(t *testing.T) {
	recipient := newRecipient(t)
	cek := bytes.Repeat([]byte{0xC3}, 32)

	first, err := ecdhkw.Wrap(recipient.PublicKey(), cek, testProtected)
	require.NoError(t, err, "first Wrap")
	second, err := ecdhkw.Wrap(recipient.PublicKey(), cek, testProtected)
	require.NoError(t, err, "second Wrap")

	require.NotEqual(t, first.EphemeralPublicKey.Bytes(), second.EphemeralPublicKey.Bytes(),
		"ephemeral public keys are identical across wraps; expected a fresh key each time")
	require.NotEqual(t, first.WrappedCEK, second.WrappedCEK,
		"wrapped CEKs are identical across wraps; expected different output")

	// Both independently recover the same plaintext CEK.
	for i, w := range []*ecdhkw.Wrapped{first, second} {
		got, err := ecdhkw.Unwrap(recipient, w, testProtected)
		require.NoErrorf(t, err, "Unwrap copy %d", i)
		require.Equalf(t, cek, got, "Unwrap copy %d mismatch", i)
	}
}

// A wrap is bound to its ephemeral key: swapping in a different ephemeral
// public key (even a valid one) breaks the derivation and fails the unwrap.
func TestUnwrapTamperedEphemeral(t *testing.T) {
	recipient := newRecipient(t)
	cek := bytes.Repeat([]byte{0x11}, 32)

	w, err := ecdhkw.Wrap(recipient.PublicKey(), cek, testProtected)
	require.NoError(t, err, "Wrap")
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err, "generate other key")
	w.EphemeralPublicKey = other.PublicKey()

	_, err = ecdhkw.Unwrap(recipient, w, testProtected)
	require.ErrorIs(t, err, aeskw.ErrIntegrity, "Unwrap with swapped ephemeral key")
}

// A wrap is bound to the recipient's protected header: unwrapping with header
// bytes other than the ones the wrap was made under fails. This is what stops an
// attacker from rewriting the recipient's algorithm header in transit.
func TestUnwrapDifferentProtectedHeader(t *testing.T) {
	recipient := newRecipient(t)
	cek := bytes.Repeat([]byte{0x33}, 32)

	w, err := ecdhkw.Wrap(recipient.PublicKey(), cek, testProtected)
	require.NoError(t, err, "Wrap")

	// {1: -29} — ECDH-ES+A128KW rather than the -31 the wrap was made under.
	_, err = ecdhkw.Unwrap(recipient, w, []byte{0xa1, 0x01, 0x38, 0x1c})
	require.ErrorIs(t, err, aeskw.ErrIntegrity, "Unwrap under a different protected header")
}

// A low-order ephemeral point would force the ECDH shared secret into a small
// subgroup; crypto/ecdh rejects it, and Unwrap must surface that as an error
// rather than deriving a KEK from a degenerate secret.
func TestUnwrapLowOrderEphemeral(t *testing.T) {
	recipient := newRecipient(t)
	// The all-zero u-coordinate is a classic X25519 low-order point. It is a
	// valid 32-byte public key to construct, but ECDH against it fails.
	lowOrder, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	require.NoError(t, err, "construct low-order point")
	w := &ecdhkw.Wrapped{EphemeralPublicKey: lowOrder, WrappedCEK: make([]byte, 40)}
	_, err = ecdhkw.Unwrap(recipient, w, testProtected)
	require.Error(t, err, "Unwrap with low-order ephemeral point should fail")
}

// A wrap is bound to its wrapped bytes: flipping any bit fails the unwrap.
func TestUnwrapTamperedCEK(t *testing.T) {
	recipient := newRecipient(t)
	cek := bytes.Repeat([]byte{0x22}, 32)

	w, err := ecdhkw.Wrap(recipient.PublicKey(), cek, testProtected)
	require.NoError(t, err, "Wrap")
	for i := range w.WrappedCEK {
		tampered := &ecdhkw.Wrapped{
			EphemeralPublicKey: w.EphemeralPublicKey,
			WrappedCEK:         bytes.Clone(w.WrappedCEK),
		}
		tampered.WrappedCEK[i] ^= 0x01
		_, err = ecdhkw.Unwrap(recipient, tampered, testProtected)
		require.ErrorIsf(t, err, aeskw.ErrIntegrity, "tampering wrapped byte %d not detected", i)
	}
}

func TestWrapInputValidation(t *testing.T) {
	recipient := newRecipient(t)
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err, "generate P256 key")

	tests := []struct {
		name string
		pub  *ecdh.PublicKey
		cek  []byte
	}{
		{"nil public key", nil, make([]byte, 32)},
		{"wrong curve", p256.PublicKey(), make([]byte, 32)},
		{"cek too short", recipient.PublicKey(), make([]byte, 8)},
		{"cek not block-aligned", recipient.PublicKey(), make([]byte, 20)},
		{"nil cek", recipient.PublicKey(), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ecdhkw.Wrap(tc.pub, tc.cek, testProtected)
			require.Error(t, err)
		})
	}
}

func TestUnwrapInputValidation(t *testing.T) {
	recipient := newRecipient(t)
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err, "generate P256 key")
	valid, err := ecdhkw.Wrap(recipient.PublicKey(), make([]byte, 32), testProtected)
	require.NoError(t, err, "Wrap")

	t.Run("nil private key", func(t *testing.T) {
		_, err := ecdhkw.Unwrap(nil, valid, testProtected)
		require.Error(t, err)
	})
	t.Run("nil wrapped", func(t *testing.T) {
		_, err := ecdhkw.Unwrap(recipient, nil, testProtected)
		require.Error(t, err)
	})
	t.Run("nil ephemeral key", func(t *testing.T) {
		_, err := ecdhkw.Unwrap(recipient, &ecdhkw.Wrapped{WrappedCEK: valid.WrappedCEK}, testProtected)
		require.Error(t, err)
	})
	t.Run("ephemeral wrong curve", func(t *testing.T) {
		w := &ecdhkw.Wrapped{EphemeralPublicKey: p256.PublicKey(), WrappedCEK: valid.WrappedCEK}
		_, err := ecdhkw.Unwrap(recipient, w, testProtected)
		require.Error(t, err)
	})
}

// TestKnownAnswerVector pins the ECDH-ES+A256KW construction to a fixed
// decryption vector: a known recipient private key, ephemeral public key, and
// wrapped CEK must Unwrap to a known CEK. This is the gold vector for the
// cross-implementation tests (foc-encryption / FIL-473). Encryption is
// nondeterministic (a fresh ephemeral key per wrap), so the shared anchor is
// the decrypt direction — which any conforming implementation must reproduce
// without an injection seam. It exercises the full path end to end: X25519
// ECDH, HKDF-SHA-256 over the COSE_KDF_Context (kdf.go), and AES-KW unwrap.
//
// The wrapped bytes were produced by an independent implementation (Python
// cryptography: X25519 exchange, HKDF-SHA-256, AES key wrap), not by this
// package, so the vector checks the Go code against something other than
// itself. The context is the RFC 9053 §5.2 structure documented in kdf.go:
// AlgorithmID = A256KW, keyDataLength = 256, empty PartyU/PartyV, and the
// recipient protected header {1: -31} that FEE puts on the wire.
func TestKnownAnswerVector(t *testing.T) {
	const (
		recipientPrivHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
		ephemeralPubHex  = "605a725d2a4adfeeb1a29e17edd621c1b7593ee8cdbc44ac6c4ab6e2f805d23c"
		wrappedCEKHex    = "97d1e9c712912ea98727d000a9ba2f9f6a8bbb07c18696bfa6d5b7f8f2cf59177883691e7dd2e8d9"
		cekHex           = "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"

		// Derived from recipientPrivHex; recorded so a cross-impl test starts
		// from the same recipient key.
		wantRecipientPubHex = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
	)

	priv, err := ecdh.X25519().NewPrivateKey(mustDecode(t, recipientPrivHex))
	require.NoError(t, err, "recipient private key")
	require.Equal(t, wantRecipientPubHex, hex.EncodeToString(priv.PublicKey().Bytes()), "recipient public key")

	ephemeralPub, err := ecdh.X25519().NewPublicKey(mustDecode(t, ephemeralPubHex))
	require.NoError(t, err, "ephemeral public key")

	w := &ecdhkw.Wrapped{EphemeralPublicKey: ephemeralPub, WrappedCEK: mustDecode(t, wrappedCEKHex)}
	got, err := ecdhkw.Unwrap(priv, w, testProtected)
	require.NoError(t, err, "unwrap")
	require.Equal(t, cekHex, hex.EncodeToString(got), "unwrapped CEK")
}
