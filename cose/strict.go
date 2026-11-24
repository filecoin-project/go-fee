package cose

import (
	"encoding/binary"
	"fmt"
)

// maxStrictDepth bounds how deeply checkStrictEncoding descends into nested
// arrays and maps, so a hostile envelope cannot exhaust the stack. It matches
// maxNestedLevels, the limit the CBOR decoder itself applies.
const maxStrictDepth = maxNestedLevels

// checkStrictEncoding reports whether data is exactly one CBOR item encoded
// under the strict profile [WithStrictEncoding] enables: every length and
// integer argument in its shortest form, no indefinite-length items, no
// floating-point values, no simple values other than false, true and null, no
// reserved additional-information values, and no tags except, when outerTag is
// set, the one tag that wraps the whole item (a COSE envelope's 16 or 96).
// Byte strings are not descended into; a caller checks nested CBOR (a
// protected header) separately.
func checkStrictEncoding(data []byte, outerTag bool) error {
	start := 0
	if outerTag && len(data) > 0 && data[0]>>5 == 6 {
		_, i, err := strictArgument(data, 1, data[0]&0x1f)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		start = i
	}
	next, err := strictItem(data, start, 0)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if next != len(data) {
		return fmt.Errorf("%w: %d bytes follow the CBOR item", ErrMalformed, len(data)-next)
	}
	return nil
}

// strictItem checks the item starting at data[i] and returns the offset just
// past it.
func strictItem(data []byte, i, depth int) (int, error) {
	if depth > maxStrictDepth {
		return 0, fmt.Errorf("CBOR nested deeper than %d levels", maxStrictDepth)
	}
	if i >= len(data) {
		return 0, fmt.Errorf("truncated CBOR item")
	}
	major, info := data[i]>>5, data[i]&0x1f
	i++

	if major == 7 {
		switch {
		case info >= 20 && info <= 22:
			return i, nil // false, true, null
		case info < 24:
			return 0, fmt.Errorf("simple value %d", info) // undefined and unassigned
		case info == 24:
			return 0, fmt.Errorf("simple value")
		case info <= 27:
			return 0, fmt.Errorf("floating-point value")
		case info == 31:
			return 0, fmt.Errorf("unexpected break")
		default:
			return 0, fmt.Errorf("reserved additional information %d", info)
		}
	}

	arg, i, err := strictArgument(data, i, info)
	if err != nil {
		return 0, err
	}
	switch major {
	case 0, 1: // unsigned and negative integers
		return i, nil
	case 2, 3: // byte and text strings
		if arg > uint64(len(data)-i) {
			return 0, fmt.Errorf("truncated string")
		}
		return i + int(arg), nil
	case 4, 5: // arrays and maps
		items := arg
		if major == 5 {
			if items > uint64(len(data)) {
				return 0, fmt.Errorf("truncated map")
			}
			items *= 2
		}
		if items > uint64(len(data)-i) {
			return 0, fmt.Errorf("truncated array or map") // every item takes at least one byte
		}
		for range items {
			if i, err = strictItem(data, i, depth+1); err != nil {
				return 0, err
			}
		}
		return i, nil
	default: // 6
		return 0, fmt.Errorf("tag %d", arg)
	}
}

// strictArgument reads the argument that follows an initial byte with the
// given additional information, rejecting indefinite lengths, reserved values
// and any argument not in its shortest form.
func strictArgument(data []byte, i int, info byte) (uint64, int, error) {
	var arg, floor uint64
	switch {
	case info < 24:
		return uint64(info), i, nil
	case info == 24:
		if i+1 > len(data) {
			return 0, 0, fmt.Errorf("truncated argument")
		}
		arg, floor, i = uint64(data[i]), 24, i+1
	case info == 25:
		if i+2 > len(data) {
			return 0, 0, fmt.Errorf("truncated argument")
		}
		arg, floor, i = uint64(binary.BigEndian.Uint16(data[i:])), 1<<8, i+2
	case info == 26:
		if i+4 > len(data) {
			return 0, 0, fmt.Errorf("truncated argument")
		}
		arg, floor, i = uint64(binary.BigEndian.Uint32(data[i:])), 1<<16, i+4
	case info == 27:
		if i+8 > len(data) {
			return 0, 0, fmt.Errorf("truncated argument")
		}
		arg, floor, i = binary.BigEndian.Uint64(data[i:]), 1<<32, i+8
	case info == 31:
		return 0, 0, fmt.Errorf("indefinite-length item")
	default:
		return 0, 0, fmt.Errorf("reserved additional information %d", info)
	}
	if arg < floor {
		return 0, 0, fmt.Errorf("argument %d not in its shortest form", arg)
	}
	return arg, i, nil
}
