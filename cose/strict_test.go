package cose

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestCheckStrictEncoding pins the strict profile item by item: shortest-form
// arguments, definite lengths, no floats, nothing reserved, exactly one item.
func TestCheckStrictEncoding(t *testing.T) {
	deep := append(bytes.Repeat([]byte{0x81}, maxStrictDepth+1), 0x00)

	valid := map[string][]byte{
		"small int":            mustHex(t, "17"),
		"one-byte argument":    mustHex(t, "1818"),
		"two-byte argument":    mustHex(t, "190100"),
		"four-byte argument":   mustHex(t, "1a00010000"),
		"eight-byte argument":  mustHex(t, "1b0000000100000000"),
		"negative int":         mustHex(t, "3a00010000"),
		"byte string":          mustHex(t, "43010203"),
		"text string":          mustHex(t, "6161"),
		"nested array and map": mustHex(t, "82a1010280"),
		"tag":                  mustHex(t, "d0f6"),
		"false true null":      mustHex(t, "83f4f5f6"),
		"simple value":         mustHex(t, "f820"),
	}
	for name, data := range valid {
		require.NoError(t, checkStrictEncoding(data), name)
	}

	invalid := map[string][]byte{
		"non-minimal one-byte argument":   mustHex(t, "1805"),
		"non-minimal two-byte argument":   mustHex(t, "1900ff"),
		"non-minimal four-byte argument":  mustHex(t, "1a0000ffff"),
		"non-minimal eight-byte argument": mustHex(t, "1b00000000ffffffff"),
		"non-minimal string length":       mustHex(t, "580161"),
		"half float":                      mustHex(t, "f93e00"),
		"single float":                    mustHex(t, "fa3fc00000"),
		"double float":                    mustHex(t, "fb3ff8000000000000"),
		"indefinite byte string":          mustHex(t, "5f41ff"),
		"indefinite array":                mustHex(t, "9f00ff"),
		"indefinite map":                  mustHex(t, "bf0102ff"),
		"lone break":                      mustHex(t, "ff"),
		"reserved additional info":        mustHex(t, "1c"),
		"non-minimal simple value":        mustHex(t, "f810"),
		"truncated string":                mustHex(t, "4301"),
		"truncated array":                 mustHex(t, "8201"),
		"trailing bytes":                  mustHex(t, "0000"),
		"too deeply nested":               deep,
	}
	for name, data := range invalid {
		require.ErrorIs(t, checkStrictEncoding(data), ErrMalformed, name)
	}
}

// TestDecodeWithStrictEncoding: the option rejects an envelope whose outer
// item or nested protected header breaks the strict profile, and the same
// bytes still decode without it.
func TestDecodeWithStrictEncoding(t *testing.T) {
	cases := map[string]string{
		// 16([ h'a10101', {}, null ]) with the protected {1: 1} as {1: 24(1)}
		"non-minimal int in the protected header": "d08344a1011801a0f6",
		"float in the unprotected header":         "d08343a10101a101f93e00f6",
		"indefinite unprotected map":              "d08343a10101bffff6",
	}
	for name, h := range cases {
		data := mustHex(t, h)
		_, _, err := Decode(data)
		require.NoError(t, err, "%s: decodes without the option", name)
		_, _, err = Decode(data, WithStrictEncoding())
		require.ErrorIs(t, err, ErrMalformed, name)
		_, _, err = DecodeReader(bytes.NewReader(data), WithStrictEncoding())
		require.ErrorIs(t, err, ErrMalformed, "%s: DecodeReader", name)
	}

	_, _, err := Decode(mustHex(t, "d08343a10101a0f6"), WithStrictEncoding())
	require.NoError(t, err, "a strictly encoded envelope decodes")
}
