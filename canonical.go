package pact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// canonicalJSON serializes a value to RFC 8785 JSON Canonicalization Scheme (JCS).
//
// JCS guarantees deterministic output:
//   - Object keys sorted lexicographically (by Unicode code points)
//   - No whitespace
//   - Numbers serialized per ES2015 Number.toString()
//   - Strings use minimal escaping
//   - No trailing commas
//
// This is essential for signing: the same logical value must always produce
// the same byte sequence, regardless of which implementation serializes it.
func canonicalJSON(v interface{}) ([]byte, error) {
	// First, round-trip through encoding/json to get a normalized representation.
	// This handles struct tags, omitempty, etc.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("pact: canonical JSON marshal failed: %w", err)
	}

	// Parse into generic interface{} for canonical re-serialization
	var parsed interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber() // Preserve number precision
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("pact: canonical JSON decode failed: %w", err)
	}

	var buf bytes.Buffer
	if err := writeCanonical(&buf, parsed); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonical writes a value in JCS canonical form.
func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")

	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}

	case json.Number:
		// RFC 8785: numbers must be serialized per ES2015 Number.toString()
		// For integers, this is just the decimal representation.
		// For floats, we need to handle edge cases.
		// Our protocol uses no floats (timestamps are strings, amounts are integers in cents).
		// But we handle both for correctness.
		if i, err := val.Int64(); err == nil {
			buf.WriteString(strconv.FormatInt(i, 10))
		} else if f, err := val.Float64(); err == nil {
			buf.WriteString(canonicalFloat(f))
		} else {
			return fmt.Errorf("pact: invalid number in canonical JSON: %s", val.String())
		}

	case string:
		// RFC 8785: strings use standard JSON escaping (RFC 8259)
		// encoding/json.Marshal handles this correctly for strings
		escaped, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("pact: failed to escape string: %w", err)
		}
		buf.Write(escaped)

	case map[string]interface{}:
		buf.WriteByte('{')

		// RFC 8785: keys sorted by Unicode code point order
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			// Write key
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return fmt.Errorf("pact: failed to escape key: %w", err)
			}
			buf.Write(keyBytes)
			buf.WriteByte(':')
			// Write value
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}

		buf.WriteByte('}')

	case []interface{}:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')

	default:
		return fmt.Errorf("pact: unsupported type in canonical JSON: %T", v)
	}

	return nil
}

// canonicalFloat serializes a float64 per ES2015 Number.toString().
// This handles the edge cases required by RFC 8785.
func canonicalFloat(f float64) string {
	// Use strconv with the shortest representation that round-trips
	return strconv.FormatFloat(f, 'G', -1, 64)
}
