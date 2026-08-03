package ecdhkw

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoErrorf(t, err, "bad hex %q", s)
	return b
}

// TestKDFContextCanonical pins the exact CBOR encoding of the COSE_KDF_Context
// for the parameters this package uses (AlgorithmID = A256KW = -5, 256-bit
// derived key, empty protected header). The bytes are the canonical, shortest-
// form encoding of:
//
//	[ -5, [null,null,null], [null,null,null], [256, h''] ]
//
// A divergence here would silently change every derived KEK, so this is the
// anchor for cross-implementation compatibility.
func TestKDFContextCanonical(t *testing.T) {
	got := kdfContext(algA256KW, kekLen*8, nil)
	want := mustDecode(t, "842483f6f6f6"+"83f6f6f6"+"8219010040")
	require.Equal(t, want, got, "kdfContext mismatch")
}

// TestKDFContextProtected confirms a non-empty protected header is embedded as
// a CBOR byte string verbatim (so the structure stays correct if a future
// caller does carry one).
func TestKDFContextProtected(t *testing.T) {
	got := kdfContext(algA256KW, kekLen*8, []byte{0xa1, 0x01, 0x38, 0x1e})
	// ...trailing SuppPubInfo: [256, h'a101381e'] -> 82 19 0100 44 a101381e
	want := mustDecode(t, "842483f6f6f6"+"83f6f6f6"+"821901004"+"4a101381e")
	require.Equal(t, want, got, "kdfContext(protected) mismatch")
}

// TestHKDFPublishedVector pins the key derivation to a published, external
// answer: the COSE-WG example ecdh-wrap-examples/p256-wrap-128-01, which
// records the ECDH shared secret, the COSE_KDF_Context, and the resulting KEK.
// Reproducing its KEK is what makes this package's derivation the one an
// RFC 9053 implementation computes; every other test in the package checks the
// code against itself.
//
// The example is ECDH-ES+A128KW over P-256, so its context carries a different
// AlgorithmID (-3), key length (128), and protected header than FEE uses. The
// curve and the wrap algorithm do not enter the derivation — only the shared
// secret, the context, and the output length do — so the vector still pins the
// construction.
func TestHKDFPublishedVector(t *testing.T) {
	z := mustDecode(t, "ee45f7c389fdb89923ca67c0e0cd29802dec8f514eb818054beedd5dafa78048")
	// [ -3, [null,null,null], [null,null,null], [128, h'a101381c'] ]
	context := mustDecode(t, "842283f6f6f683f6f6f682188044a101381c")

	got, err := hkdfKEK(z, context, 16)
	require.NoError(t, err, "hkdfKEK")
	require.Equal(t, "7c60cb35a78b24dcf40a394395e9e8cd", hex.EncodeToString(got), "KEK mismatch")
}

// TestHKDFExtractExpand checks the derivation against an independent spelling
// of RFC 5869: HMAC-SHA-256 extract with an all-zero salt, then one expand
// round of HMAC(PRK, info || 0x01). One round covers the 32-byte A256KW case
// exactly, since SHA-256 emits 32 bytes.
func TestHKDFExtractExpand(t *testing.T) {
	z := bytes.Repeat([]byte{0xAB}, 32)
	info := []byte("other-info")

	got, err := hkdfKEK(z, info, 32)
	require.NoError(t, err, "hkdfKEK")

	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(z)
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write(info)
	expand.Write([]byte{0x01})
	want := expand.Sum(nil)

	require.Equal(t, want, got, "hkdfKEK single block mismatch")
}

// TestHKDFMultiBlock checks an output longer than one hash block: the second
// expand round feeds the previous block back in, per RFC 5869 §2.3.
func TestHKDFMultiBlock(t *testing.T) {
	z := bytes.Repeat([]byte{0x07}, 32)
	info := []byte("ctx")

	got, err := hkdfKEK(z, info, 48)
	require.NoError(t, err, "hkdfKEK")
	require.Len(t, got, 48)

	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(z)
	prk := extract.Sum(nil)

	block := func(prev []byte, counter byte) []byte {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{counter})
		return h.Sum(nil)
	}
	first := block(nil, 1)
	want := append(bytes.Clone(first), block(first, 2)...)[:48]

	require.Equal(t, want, got, "hkdfKEK multi block mismatch")
}

// TestHKDFContextSensitivity confirms the derived key depends on the context
// bytes — derivations under different contexts must not collide.
func TestHKDFContextSensitivity(t *testing.T) {
	z := bytes.Repeat([]byte{0x42}, 32)
	a, err := hkdfKEK(z, kdfContext(algA256KW, 256, nil), 32)
	require.NoError(t, err, "hkdfKEK(256)")
	b, err := hkdfKEK(z, kdfContext(algA256KW, 128, nil), 32)
	require.NoError(t, err, "hkdfKEK(128)")
	require.NotEqual(t, a, b, "derivations under different keyDataLength contexts collided")
}

// TestHKDFProtectedSensitivity confirms the recipient's protected header is
// bound into the derivation: the same secret under an empty and a non-empty
// protected header must give different keys. Without this binding an attacker
// could rewrite the recipient's algorithm header and the unwrap would still
// succeed.
func TestHKDFProtectedSensitivity(t *testing.T) {
	z := bytes.Repeat([]byte{0x42}, 32)
	empty, err := hkdfKEK(z, kdfContext(algA256KW, 256, nil), 32)
	require.NoError(t, err, "hkdfKEK(empty protected)")
	set, err := hkdfKEK(z, kdfContext(algA256KW, 256, []byte{0xa1, 0x01, 0x38, 0x1e}), 32)
	require.NoError(t, err, "hkdfKEK(protected)")
	require.NotEqual(t, empty, set, "derivations under different protected headers collided")
}

// TestCBORHeadEncoding pins the shortest-form (canonical) CBOR head encoding
// across every argument-size class, for the major types the context uses.
func TestCBORHeadEncoding(t *testing.T) {
	tests := []struct {
		name  string
		major byte
		arg   uint64
		want  string
	}{
		{"uint tiny", cborUint, 0, "00"},
		{"uint max inline", cborUint, 23, "17"},
		{"uint 1-byte", cborUint, 24, "1818"},
		{"uint 1-byte max", cborUint, 255, "18ff"},
		{"uint 2-byte", cborUint, 256, "190100"},
		{"uint 2-byte max", cborUint, 65535, "19ffff"},
		{"uint 4-byte", cborUint, 65536, "1a00010000"},
		{"uint 4-byte max", cborUint, 1<<32 - 1, "1affffffff"},
		{"uint 8-byte", cborUint, 1 << 32, "1b0000000100000000"},
		{"array(4)", cborArray, 4, "84"},
		{"empty bstr", cborBytes, 0, "40"},
		{"4-byte bstr", cborBytes, 4, "44"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hex.EncodeToString(cborHead(nil, tc.major, tc.arg))
			require.Equalf(t, tc.want, got, "cborHead(%d, %d)", tc.major, tc.arg)
		})
	}
}

// TestCBORIntEncoding pins the integer encoding, including the negative range
// (CBOR major type 1, argument = -1-n) used for the algorithm identifier.
func TestCBORIntEncoding(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "00"},
		{23, "17"},
		{24, "1818"},
		{-1, "20"},
		{-5, "24"}, // A256KW
		{-24, "37"},
		{-25, "3818"},
		{-256, "38ff"},
		{-257, "390100"},
	}
	for _, tc := range tests {
		got := hex.EncodeToString(cborInt(nil, tc.n))
		require.Equalf(t, tc.want, got, "cborInt(%d)", tc.n)
	}
}
