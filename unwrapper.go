package fee

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/filecoin-project/go-fee/aeskw"
	"github.com/filecoin-project/go-fee/aesstream"
	"github.com/filecoin-project/go-fee/cose"
	"github.com/filecoin-project/go-fee/ecdhkw"
)

// RecipientUnwrapper holds the keys [Decrypt] and [DecryptRange] may use to
// recover a content-encryption key (CEK) from an envelope's recipients. Build
// one per key with [NewECDHESUnwrapper] or [NewA256KWUnwrapper], and combine
// several with [MultiUnwrapper]. (When the CEK is supplied out of band rather
// than carried in the envelope, use [DecryptWithCEK] and no unwrapper.)
//
// Recipients are tried in envelope order, and each against the keys that may
// hold it, until one unwraps:
//
//   - A key is only tried against a recipient of its own key-wrap algorithm.
//   - A recipient with a kid is tried first with the keys whose kid equals it,
//     then with the keys that have none. A key with a different kid is never
//     tried.
//   - A recipient without a kid is tried with every key, in the order given.
//
// A key that fails the key-wrap integrity check is not an error: the next
// candidate is tried. At most [MaxUnwrapAttempts] unwraps are attempted per
// call.
//
// RecipientUnwrapper is a sealed interface: the only implementations are the
// ones constructed by [NewECDHESUnwrapper], [NewA256KWUnwrapper] and
// [MultiUnwrapper], mirroring the wrap side.
type RecipientUnwrapper interface {
	// keys returns the keys this unwrapper holds, in try order.
	keys() []unwrapKey
}

// unwrapKey is one key a [RecipientUnwrapper] holds.
type unwrapKey interface {
	// keyID returns the kid the key is known by, or nil if it has none.
	keyID() []byte
	// alg returns the key-wrap algorithm the key recovers CEKs for.
	alg() int64
	// unwrap recovers the CEK from a recipient of the key's algorithm. A wrong
	// key fails with an error wrapping [aeskw.ErrIntegrity].
	unwrap(r *cose.Recipient) ([]byte, error)
}

// MaxUnwrapAttempts bounds how many recipient unwraps one [Decrypt] or
// [DecryptRange] call attempts before failing with [ErrUnwrapAttemptLimit], so
// an envelope with many kid-less recipients cannot make a decryptor holding
// many keys do unbounded work. It matches the Synapse SDK's default.
const MaxUnwrapAttempts = 64

// ecdhESUnwrapper recovers a CEK wrapped with ECDH-ES+A256KW using an X25519
// private key.
type ecdhESUnwrapper struct {
	kid  []byte
	priv *ecdh.PrivateKey
}

// NewECDHESUnwrapper returns a [RecipientUnwrapper] that recovers a CEK wrapped
// to the X25519 public key matching priv. kid is the recipient key id — the
// same value passed to [NewECDHESRecipient] — or nil for a key without one,
// which is tried against every ECDH-ES+A256KW recipient. priv must be an X25519
// key.
func NewECDHESUnwrapper(kid []byte, priv *ecdh.PrivateKey) RecipientUnwrapper {
	return &ecdhESUnwrapper{kid: kid, priv: priv}
}

func (u *ecdhESUnwrapper) keys() []unwrapKey { return []unwrapKey{u} }
func (u *ecdhESUnwrapper) keyID() []byte     { return u.kid }
func (u *ecdhESUnwrapper) alg() int64        { return cose.AlgECDHESA256KW }

func (u *ecdhESUnwrapper) unwrap(r *cose.Recipient) ([]byte, error) {
	ephPub, err := ephemeralX25519(r.Headers.Unprotected)
	if err != nil {
		return nil, err
	}
	// The protected header is an input to the key derivation (RFC 9053 §5.2), and
	// ProtectedBytes hands back the bytes as they arrived on the wire, so a
	// sender whose encoder differs from ours still unwraps.
	protected, err := r.Headers.ProtectedBytes()
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH-ES recipient protected header: %v", ErrMalformedEnvelope, err)
	}
	cek, err := ecdhkw.Unwrap(u.priv, &ecdhkw.Wrapped{
		EphemeralPublicKey: ephPub,
		WrappedCEK:         r.Ciphertext,
	}, protected)
	if err != nil {
		return nil, fmt.Errorf("fee: ECDH-ES+A256KW unwrap: %w", err)
	}
	return cek, nil
}

// ephemeralX25519 extracts the sender's ephemeral X25519 public key from a
// recipient's ephemeral-key header. The ephemeral key is a self-describing
// COSE_Key map (see the coseKey* constants in recipient.go): its kty must be OKP
// and its crv X25519, and the public key travels in the x parameter (label -2).
// A missing header, a non-COSE_Key value, a mismatched key type or curve, or an
// invalid point is reported as [ErrMalformedEnvelope].
func ephemeralX25519(unprotected cose.Header) (*ecdh.PublicKey, error) {
	raw, ok := unprotected.Get(cose.HeaderLabelEphemeralKey)
	if !ok {
		return nil, fmt.Errorf("%w: ECDH-ES recipient missing ephemeral key", ErrMalformedEnvelope)
	}
	key, ok := raw.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: ECDH-ES ephemeral key is not a COSE_Key map", ErrMalformedEnvelope)
	}
	if kty, ok := key[coseKeyLabelKty].(int64); !ok || kty != coseKeyTypeOKP {
		return nil, fmt.Errorf("%w: ECDH-ES ephemeral key type is not OKP", ErrMalformedEnvelope)
	}
	if crv, ok := key[coseKeyLabelCrv].(int64); !ok || crv != coseKeyCurveX25519 {
		return nil, fmt.Errorf("%w: ECDH-ES ephemeral key curve is not X25519", ErrMalformedEnvelope)
	}
	x, ok := key[coseKeyLabelXCoord].([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: ECDH-ES ephemeral key missing x coordinate", ErrMalformedEnvelope)
	}
	pub, err := ecdh.X25519().NewPublicKey(x)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH-ES ephemeral key: %v", ErrMalformedEnvelope, err)
	}
	return pub, nil
}

// a256kwUnwrapper recovers a CEK wrapped with A256KW under a symmetric KEK.
type a256kwUnwrapper struct {
	kid []byte
	kek []byte
}

// NewA256KWUnwrapper returns a [RecipientUnwrapper] that recovers a CEK wrapped
// under kek with A256KW. kid is the recipient key id — the same value passed to
// [NewA256KWRecipient] — or nil for a key without one, which is tried against
// every A256KW recipient. kek must be the 32-byte KEK the CEK was wrapped
// under.
func NewA256KWUnwrapper(kid, kek []byte) RecipientUnwrapper {
	return &a256kwUnwrapper{kid: kid, kek: kek}
}

func (u *a256kwUnwrapper) keys() []unwrapKey { return []unwrapKey{u} }
func (u *a256kwUnwrapper) keyID() []byte     { return u.kid }
func (u *a256kwUnwrapper) alg() int64        { return cose.AlgA256KW }

func (u *a256kwUnwrapper) unwrap(r *cose.Recipient) ([]byte, error) {
	cek, err := aeskw.Unwrap(u.kek, r.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("fee: A256KW unwrap: %w", err)
	}
	return cek, nil
}

// multiUnwrapper holds the keys of several unwrappers.
type multiUnwrapper []unwrapKey

// MultiUnwrapper returns a [RecipientUnwrapper] holding the keys of every
// unwrapper given, tried in that order, so one decrypt can use any of a
// caller's keys. It is how a caller holding several keys decrypts an envelope
// whose recipients carry no kid: [Decrypt] consumes its reader, so trying each
// key in a separate call is not possible.
func MultiUnwrapper(unwrappers ...RecipientUnwrapper) RecipientUnwrapper {
	var m multiUnwrapper
	for _, u := range unwrappers {
		if u == nil {
			// An entry that cannot be used makes the whole unwrapper unusable,
			// so Decrypt reports ErrNilUnwrapper rather than silently skipping it.
			return nil
		}
		m = append(m, u.keys()...)
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func (m multiUnwrapper) keys() []unwrapKey { return m }

// recoverCEK recovers the CEK from an envelope's recipients with the keys u
// holds, in the order [RecipientUnwrapper] documents. A key that fails the
// key-wrap integrity check moves on to the next candidate; any other unwrap
// failure is returned at once. If no candidate unwraps it returns
// [ErrNoMatchingRecipient], wrapping the last integrity failure if there was
// one, and [ErrUnwrapAttemptLimit] once [MaxUnwrapAttempts] unwraps have
// failed. The recipients must already have passed [validateRecipients].
func recoverCEK(recipients []*cose.Recipient, u RecipientUnwrapper) ([]byte, error) {
	keys := u.keys()
	attempts := 0
	var lastErr error
	for _, r := range recipients {
		alg, ok := recipientAlg(r)
		if !ok {
			continue // a text algorithm, which no key here handles
		}
		kid, hasKID := recipientKID(r)
		for _, k := range candidateKeys(keys, alg, kid, hasKID) {
			if attempts == MaxUnwrapAttempts {
				return nil, ErrUnwrapAttemptLimit
			}
			attempts++
			cek, err := k.unwrap(r)
			if err == nil {
				return cek, nil
			}
			if !errors.Is(err, aeskw.ErrIntegrity) {
				return nil, err
			}
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoMatchingRecipient, lastErr)
	}
	return nil, ErrNoMatchingRecipient
}

// candidateKeys returns the keys to try against one recipient, in try order:
// for a recipient with a kid, the keys with an equal kid and then the keys with
// none; for a recipient without one, every key. Only keys of the recipient's
// algorithm are candidates. An empty kid on a key counts as none.
func candidateKeys(keys []unwrapKey, alg int64, kid []byte, hasKID bool) []unwrapKey {
	var exact, wildcard []unwrapKey
	for _, k := range keys {
		switch {
		case k.alg() != alg:
		case !hasKID || len(k.keyID()) == 0:
			wildcard = append(wildcard, k)
		case bytes.Equal(k.keyID(), kid):
			exact = append(exact, k)
		}
	}
	return append(exact, wildcard...)
}

// recipientUnderstoodLabels are the recipient header parameters a recipient
// may list as critical: alg and kid. crit itself would be circular, and the
// ECDH-ES ephemeral key is read only from the unprotected header, where crit
// cannot name it.
var recipientUnderstoodLabels = map[int64]bool{
	cose.HeaderLabelAlg: true, cose.HeaderLabelKID: true,
}

// a256kwWrappedSize is the wire length of an A256KW-wrapped CEK: the 32-byte key
// plus RFC 3394's 8-byte integrity block.
const a256kwWrappedSize = aesstream.KeySize + 8

// validateRecipients checks the structure of every recipient in an envelope,
// before any is selected or unwrapped, so an envelope with a malformed
// recipient is refused whichever recipient, if any, the caller would use. See
// [validateRecipient] for the rules.
func validateRecipients(recipients []*cose.Recipient) error {
	for i, r := range recipients {
		if err := validateRecipient(r); err != nil {
			return fmt.Errorf("recipient %d: %w", i, err)
		}
	}
	return nil
}

// validateRecipient checks one recipient's headers: crit is processed (only
// alg and kid may be named); no label appears in both buckets; kid, wherever it
// is, is a byte string; alg is present, as an integer or a text string. For
// the algorithms FEE profiles it also checks placement: an A256KW recipient's
// protected header is empty (RFC 9053 §6.2.1), so its alg is unprotected, and
// its wrapped key is exactly 40 bytes; an ECDH-ES+A256KW recipient's alg is
// protected, since those bytes feed its key derivation, and it carries a valid
// X25519 ephemeral key. A recipient that passes can fail to unwrap only by
// being wrapped under a different key.
func validateRecipient(r *cose.Recipient) error {
	h := r.Headers
	if err := checkCrit(h, recipientUnderstoodLabels); err != nil {
		return err
	}
	if err := checkDisjoint(h); err != nil {
		return err
	}
	for _, m := range []cose.Header{h.Protected, h.Unprotected} {
		if v, ok := m.Get(cose.HeaderLabelKID); ok {
			if _, ok := v.([]byte); !ok {
				return fmt.Errorf("%w: kid is not a byte string", ErrMalformedEnvelope)
			}
		}
	}

	algProtected := h.Protected.Has(cose.HeaderLabelAlg)
	algHeader := h.Unprotected
	if algProtected {
		algHeader = h.Protected
	}
	alg, ok := algHeader.Get(cose.HeaderLabelAlg)
	if !ok {
		return fmt.Errorf("%w: recipient names no algorithm", ErrMalformedEnvelope)
	}
	switch alg.(type) {
	case int64, string:
	default:
		return fmt.Errorf("%w: recipient algorithm is neither an integer nor a text string", ErrMalformedEnvelope)
	}

	switch alg {
	case cose.AlgA256KW:
		if prot, err := h.ProtectedBytes(); err != nil || len(prot) != 0 {
			return fmt.Errorf("%w: A256KW recipient protected header must be empty", ErrMalformedEnvelope)
		}
		if len(r.Ciphertext) != a256kwWrappedSize {
			return fmt.Errorf("%w: A256KW wrapped key is %d bytes, want %d", ErrMalformedEnvelope, len(r.Ciphertext), a256kwWrappedSize)
		}
	case cose.AlgECDHESA256KW:
		if !algProtected {
			return fmt.Errorf("%w: ECDH-ES+A256KW recipient algorithm must be protected", ErrMalformedEnvelope)
		}
		if _, err := ephemeralX25519(h.Unprotected); err != nil {
			return err
		}
	}
	return nil
}

// recipientAlg returns the key-wrap algorithm of a recipient that
// [validateRecipient] has accepted, from whichever bucket carries it. It
// reports false for a text algorithm, which no unwrapper here handles.
func recipientAlg(r *cose.Recipient) (int64, bool) {
	h := r.Headers.Unprotected
	if r.Headers.Protected.Has(cose.HeaderLabelAlg) {
		h = r.Headers.Protected
	}
	return h.Int(cose.HeaderLabelAlg)
}

// recipientKID returns a recipient's kid, read from the protected header first
// and then the unprotected one. [validateRecipient] guarantees it is in at
// most one of them.
func recipientKID(r *cose.Recipient) ([]byte, bool) {
	if kid, ok := r.Headers.Protected.Bytes(cose.HeaderLabelKID); ok {
		return kid, true
	}
	return r.Headers.Unprotected.Bytes(cose.HeaderLabelKID)
}
