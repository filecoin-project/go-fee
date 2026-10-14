package cose

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

func TestDecodeMalformed(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want error
	}{
		{"empty input", "", ErrMalformed},
		{"truncated array", "d86084", ErrMalformed},
		{"truncated mid-item", "d8608443a101", ErrMalformed},
		{"not a tag (bare array)", "8440a0f6818340a041aa", ErrNotEncrypt},
		{"bare integer, not a tag", "01", ErrNotEncrypt},
		{"unsupported tag (55799)", "d9d9f78440a0f6818340a041aa", ErrNotEncrypt},
		{"tag 16 with 4 elems (Encrypt0 shape violated)", "d08440a0f6818340a041aa", ErrMalformed},
		{"tag 96 array too short (3 elems)", "d8608340a0f6", ErrMalformed},
		{"array too long (5 elems)", "d8608540a0f6818340a041aa40", ErrMalformed},
		{"protected not a byte string", "d86084a0a0f6818340a041aa", ErrMalformed},
		{"protected content not a map", "d860844103a0f6818340a041aa", ErrMalformed},
		{"unprotected not a map", "d860844040f6818340a041aa", ErrMalformed},
		{"body ciphertext not null", "d8608440a041ff818340a041aa", ErrDetachedPayload},
		{"recipients not an array", "d8608440a0f640", ErrMalformed},
		{"recipients empty", "d8608440a0f680", ErrNoRecipients},
		{"recipient not an array", "d8608440a0f68140", ErrMalformed},
		{"recipient array too short (2)", "d8608440a0f6818240a0", ErrMalformed},
		{"recipient nested (4 elems)", "d8608440a0f6818440a041aa80", ErrMalformed},
		{"recipient ciphertext wrong type", "d8608440a0f6818340a001", ErrMalformed},
		{"duplicate protected label", "d8608445a201030104a0f6818340a041aa", ErrMalformed},
		{"duplicate unprotected label", "d8608440a201030104f6818340a041aa", ErrMalformed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Tolerate spaces in the hex literals above for readability.
			raw := hexDec(t, removeSpaces(tc.hex))
			env, rest, err := Decode(raw)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, env)
			require.Nil(t, rest)
		})
	}
}

// TestDecodeTruncatedIsUnexpectedEOF pins that a decode failing only because the
// input stopped mid-item is distinguishable from one whose bytes are complete and
// wrong. A caller reading a prefix of a larger object (see fee's envelope-header
// probe) grows its read only for the former; without this a complete-but-invalid
// item would be re-read at ever larger sizes to no purpose.
func TestDecodeTruncatedIsUnexpectedEOF(t *testing.T) {
	truncated := map[string]string{
		"empty input":        "",
		"truncated array":    "d86084",
		"truncated mid-item": "d8608443a101",
	}
	for name, h := range truncated {
		t.Run(name, func(t *testing.T) {
			_, _, err := Decode(hexDec(t, h))
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		})
	}

	// Complete items that are simply not what we accept must not look truncated,
	// however short they are.
	complete := map[string]string{
		"bare integer, not a tag":   "01",
		"tag 96 array too short":    "d8608340a0f6",
		"duplicate protected label": "d8608445a201030104a0f6818340a041aa",
		"body ciphertext not null":  "d8608440a041ff818340a041aa",
	}
	for name, h := range complete {
		t.Run(name, func(t *testing.T) {
			_, _, err := Decode(hexDec(t, h))
			require.NotErrorIs(t, err, io.ErrUnexpectedEOF)
		})
	}
}

func removeSpaces(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

func TestDecodeExpectedType(t *testing.T) {
	withType := func(typ any) []byte {
		t.Helper()
		env := &Envelope{
			Headers:    Headers{Protected: Header{}.Set(HeaderLabelType, typ)},
			Recipients: []*Recipient{{Ciphertext: []byte{0xAA}}},
		}
		b, err := env.Encode()
		require.NoError(t, err)
		return b
	}
	withoutType := func() []byte {
		t.Helper()
		env := &Envelope{
			Headers:    Headers{Protected: Header{}.Set(HeaderLabelAlg, AlgA256GCM)},
			Recipients: []*Recipient{{Ciphertext: []byte{0xAA}}},
		}
		b, err := env.Encode()
		require.NoError(t, err)
		return b
	}

	t.Run("matching type", func(t *testing.T) {
		_, _, err := Decode(withType(exampleType), WithExpectedType(exampleType))
		require.NoError(t, err)
	})

	t.Run("wrong type", func(t *testing.T) {
		_, _, err := Decode(withType("application/other"), WithExpectedType(exampleType))
		require.ErrorIs(t, err, ErrUnexpectedType)
	})

	t.Run("missing type", func(t *testing.T) {
		_, _, err := Decode(withoutType(), WithExpectedType(exampleType))
		require.ErrorIs(t, err, ErrUnexpectedType)
	})

	t.Run("type present but not a string", func(t *testing.T) {
		_, _, err := Decode(withType(int64(7)), WithExpectedType(exampleType))
		require.ErrorIs(t, err, ErrUnexpectedType)
	})

	t.Run("no check when option omitted", func(t *testing.T) {
		_, _, err := Decode(withoutType())
		require.NoError(t, err)
	})
}

// countingReader yields n zero bytes and records how many were read.
type countingReader struct{ n, read int64 }

func (c *countingReader) Read(p []byte) (int, error) {
	if c.read >= c.n {
		return 0, io.EOF
	}
	k := min(int64(len(p)), c.n-c.read)
	clear(p[:k])
	c.read += k
	return int(k), nil
}

// TestDecodeWithMaxSize: an envelope of exactly the limit decodes, one byte
// over fails as ErrTooLarge, and input that simply ends early stays a plain
// truncation. Both entry points agree, and the reader keeps the detached
// payload intact.
func TestDecodeWithMaxSize(t *testing.T) {
	header, err := sampleEnvelope().Encode()
	require.NoError(t, err)
	payload := []byte("detached-ciphertext")
	blob := append(append([]byte{}, header...), payload...)
	size := int64(len(header))

	env, rest, err := Decode(blob, WithMaxSize(size))
	require.NoError(t, err, "Decode at the limit")
	require.NotNil(t, env)
	require.Equal(t, payload, rest)

	env, restR, err := DecodeReader(bytes.NewReader(blob), WithMaxSize(size))
	require.NoError(t, err, "DecodeReader at the limit")
	require.NotNil(t, env)
	got, err := io.ReadAll(restR)
	require.NoError(t, err)
	require.Equal(t, payload, got, "the payload is read past the limit")

	_, _, err = Decode(blob, WithMaxSize(size-1))
	require.ErrorIs(t, err, ErrTooLarge, "Decode over the limit")
	require.ErrorIs(t, err, ErrMalformed)
	require.NotErrorIs(t, err, io.ErrUnexpectedEOF, "an oversized envelope is not a truncated one")
	_, _, err = DecodeReader(bytes.NewReader(blob), WithMaxSize(size-1))
	require.ErrorIs(t, err, ErrTooLarge, "DecodeReader over the limit")
	require.ErrorIs(t, err, ErrMalformed)

	truncated := header[:size-1]
	_, _, err = Decode(truncated, WithMaxSize(size+100))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF, "Decode of a truncated envelope")
	require.NotErrorIs(t, err, ErrTooLarge)
	_, _, err = DecodeReader(bytes.NewReader(truncated), WithMaxSize(size+100))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeReader of a truncated envelope")
	require.NotErrorIs(t, err, ErrTooLarge)
}

// TestDecodeReaderMaxSizeBoundsReads: an envelope declaring a 64 MiB protected
// header is refused after reading no more than the limit.
func TestDecodeReaderMaxSizeBoundsReads(t *testing.T) {
	const declared = 64 << 20
	const limit = 1 << 20
	// 96([ h'<declared bytes>' ...
	head := []byte{0xd8, 0x60, 0x84, 0x5a, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(head[4:], declared)
	body := &countingReader{n: declared}

	_, _, err := DecodeReader(io.MultiReader(bytes.NewReader(head), body), WithMaxSize(limit))
	require.ErrorIs(t, err, ErrTooLarge)
	require.LessOrEqual(t, int64(len(head))+body.read, int64(limit))
}

// TestDecodeWithMaxSizeNotPositive: a limit of zero or less is a caller error
// that fails every decode before any input is read, rather than lifting the
// limit.
func TestDecodeWithMaxSizeNotPositive(t *testing.T) {
	header, err := sampleEnvelope().Encode()
	require.NoError(t, err)
	for _, n := range []int64{0, -1} {
		_, _, err := Decode(header, WithMaxSize(n))
		require.ErrorIs(t, err, ErrInvalidMaxSize, "Decode, limit %d", n)

		r := &countingReader{n: int64(len(header))}
		_, _, err = DecodeReader(r, WithMaxSize(n))
		require.ErrorIs(t, err, ErrInvalidMaxSize, "DecodeReader, limit %d", n)
		require.Zero(t, r.read, "DecodeReader read input, limit %d", n)
	}
}

// TestParseEncStructure: an Enc_structure built by EncStructure parses back to
// its context, protected header and external AAD, for both envelope forms, and
// anything else is malformed.
func TestParseEncStructure(t *testing.T) {
	env := sampleEnvelope()
	for name, e := range map[string]*Envelope{
		"Encrypt":  env,
		"Encrypt0": {Headers: env.Headers},
	} {
		aad, err := e.EncStructure([]byte("external"))
		require.NoError(t, err)
		context, protected, external, err := ParseEncStructure(aad)
		require.NoError(t, err, name)
		require.Equal(t, name, context)
		require.Equal(t, env.Headers.Protected, protected, name)
		require.Equal(t, []byte("external"), external, name)
	}

	malformed := map[string]string{
		"not an array":                   "a0",
		"two elements":                   "82674572637279707440",
		"unknown context":                "8363666f6f4040",
		"context not text":               "83014040",
		"protected not a byte string":    "8367456e637279707401" + "40",
		"protected not a map":            "8367456e637279707441" + "01" + "40",
		"external aad not a byte string": "8367456e63727970744001",
		"non-minimal length":             "8367456e6372797074" + "5800" + "40",
		"trailing bytes":                 "8367456e63727970744040" + "00",
	}
	for name, h := range malformed {
		_, _, _, err := ParseEncStructure(hexDec(t, h))
		require.ErrorIs(t, err, ErrMalformed, name)
	}
}

// TestDecodeReaderReadError: a source that fails partway through the envelope
// is reported as that failure, not as a malformed envelope, with or without a
// size limit.
func TestDecodeReaderReadError(t *testing.T) {
	header, err := sampleEnvelope().Encode()
	require.NoError(t, err)
	boom := errors.New("connection reset")
	for name, opts := range map[string][]DecodeOption{"no limit": nil, "with a limit": {WithMaxSize(1 << 20)}} {
		r := io.MultiReader(bytes.NewReader(header[:len(header)/2]), iotest.ErrReader(boom))
		_, _, err := DecodeReader(r, opts...)
		require.ErrorIs(t, err, boom, name)
		require.NotErrorIs(t, err, ErrMalformed, name)
	}
}
