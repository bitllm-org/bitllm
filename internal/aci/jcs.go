// Package aci verifies Attested Confidential Inference reports and speaks the
// E2EE v2 field encryption, so a prompt can cross BitLLM peers sealed to a
// model server's TEE. Spec: github.com/Dstack-TEE/private-ai-gateway, spec/.
package aci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf8"
)

// canonical returns the RFC 8785 (JCS) form of a JSON value decoded with
// UseNumber. It covers what ACI hashes: objects, arrays, strings, integers,
// booleans and null. A non-integer number is refused rather than risk a
// digest that differs from the service's.
func canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeJCS(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeJCS(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case json.Number:
		i, err := x.Int64()
		if err != nil || math.Abs(float64(i)) > 1<<53 {
			return fmt.Errorf("jcs: unsupported number %s", x)
		}
		b.WriteString(strconv.FormatInt(i, 10))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case int:
		b.WriteString(strconv.Itoa(x))
	case string:
		writeJCSString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJCS(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// JCS sorts by UTF-16 code units; for the ASCII keys ACI uses this
		// is the same as a byte sort. Refuse anything else.
		for _, k := range keys {
			for i := 0; i < len(k); i++ {
				if k[i] >= 0x80 {
					return fmt.Errorf("jcs: non-ASCII key %q", k)
				}
			}
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJCSString(b, k)
			b.WriteByte(':')
			if err := writeJCS(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
	return nil
}

func writeJCSString(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hex[r>>4])
			b.WriteByte(hex[r&0xf])
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
}
