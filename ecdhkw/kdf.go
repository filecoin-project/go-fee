package ecdhkw

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// This file implements the key derivation half of ECDH-ES: turning the raw
// X25519 shared secret into the A256KW key-encryption key. Two pieces are
// involved, both pinned here so the byte layout is unambiguous for the
// cross-implementation test vectors (foc-encryption / FIL-473):
//
//  1. hkdfKEK — HKDF-SHA-256 (RFC 5869), which RFC 9053 §5.1 specifies for COSE
//     key derivation and §6.3.1 mandates for every ECDH algorithm, alg -31
//     among them.
//  2. kdfContext — the COSE_KDF_Context structure of RFC 9053 §5.2, CBOR-encoded
//     and passed to HKDF as the info parameter that binds the derived key to its
//     algorithm, length, and header.
//
// The CBOR is hand-written rather than pulled from a codec: the structure is a
// fixed four-element array of small integers and two short byte strings, so a
// dozen lines of deterministic, shortest-form encoding is clearer and lighter
// than a dependency, and it leaves no room for a codec to pick a non-canonical
// encoding that would diverge from another implementation.
//
// Note for anyone comparing against JOSE: RFC 7518 §4.6 derives its ECDH-ES key
// with the NIST SP 800-56A §5.8.1 single-step KDF, a different construction.
// COSE does not use it, and a KEK derived that way will not unwrap here.

// hkdfKEK derives keyLen bytes of key-encryption key from the ECDH shared
// secret z and the CBOR COSE_KDF_Context, using HKDF-SHA-256 (RFC 5869) as
// RFC 9053 §5.1 requires: z is the input keying material and context is the
// info parameter.
//
// The salt is empty. RFC 9053 §6.3.1 provides a salt header parameter only for
// static-static ECDH, where the sender needs to inject uniqueness by hand; the
// ephemeral-static scheme here gets that from its fresh ephemeral key, so no
// salt travels in the envelope and HKDF-Extract runs with the all-zero default.
func hkdfKEK(z, context []byte, keyLen int) ([]byte, error) {
	return hkdf.Key(sha256.New, z, nil, string(context), keyLen)
}

// kdfContext builds the CBOR-encoded COSE_KDF_Context (RFC 9053 §5.2) for a
// key-agreement-with-key-wrap derivation:
//
//	[ algID, PartyUInfo, PartyVInfo, [ keyDataLenBits, protected ] ]
//
// where PartyUInfo and PartyVInfo are each the empty PartyInfo [nil, nil, nil]
// (no identity, nonce, or other data exchanged at this layer), and SuppPubInfo
// carries the derived-key length in bits plus the protected-header byte string.
// The optional SuppPrivInfo trailer is omitted.
//
// protected is the serialized protected header of the COSE_Recipient that
// carries the wrap — for FEE, the encoding of {1: -31} — or a zero-length slice
// if that bucket is empty. algID is the COSE identifier of the algorithm the
// derived key feeds (A256KW), which binds the key to its purpose.
func kdfContext(algID int64, keyDataLenBits uint64, protected []byte) []byte {
	var b []byte
	b = cborHead(b, cborArray, 4) // [algID, PartyU, PartyV, SuppPubInfo]
	b = cborInt(b, algID)

	// PartyUInfo and PartyVInfo: the empty PartyInfo, three null slots.
	for k := 0; k < 2; k++ {
		b = cborHead(b, cborArray, 3)
		b = append(b, cborNull, cborNull, cborNull)
	}

	// SuppPubInfo: [keyDataLength (bits), protected].
	b = cborHead(b, cborArray, 2)
	b = cborHead(b, cborUint, keyDataLenBits)
	b = cborHead(b, cborBytes, uint64(len(protected)))
	b = append(b, protected...)
	return b
}

// CBOR major types (high three bits of the initial byte) and the simple value
// used here. Only the subset the context needs is defined.
const (
	cborUint  byte = 0 // major type 0: unsigned integer
	cborNint  byte = 1 // major type 1: negative integer
	cborBytes byte = 2 // major type 2: byte string
	cborArray byte = 4 // major type 4: array
	cborNull  byte = 0xf6
)

// cborHead appends a CBOR head: the major type in the high three bits followed
// by arg, encoded in the shortest form (canonical / deterministic encoding).
func cborHead(b []byte, major byte, arg uint64) []byte {
	m := major << 5
	switch {
	case arg < 24:
		return append(b, m|byte(arg))
	case arg < 1<<8:
		return append(b, m|24, byte(arg))
	case arg < 1<<16:
		return append(b, m|25, byte(arg>>8), byte(arg))
	case arg < 1<<32:
		return append(b, m|26, byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	default:
		return append(b, m|27,
			byte(arg>>56), byte(arg>>48), byte(arg>>40), byte(arg>>32),
			byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	}
}

// cborInt appends a CBOR integer, choosing the unsigned (major 0) or negative
// (major 1) encoding. A negative n is stored as the argument -1-n.
func cborInt(b []byte, n int64) []byte {
	if n < 0 {
		return cborHead(b, cborNint, uint64(-1-n))
	}
	return cborHead(b, cborUint, uint64(n))
}
