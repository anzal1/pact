package pact

import "encoding/base64"

// encodeBase64URL encodes bytes to base64url without padding (RFC 4648 §5).
func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// decodeBase64URL decodes base64url (no padding) to bytes.
func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ExportBase64URL is the exported version of encodeBase64URL for CLI use.
func ExportBase64URL(data []byte) string {
	return encodeBase64URL(data)
}

// ImportBase64URL is the exported version of decodeBase64URL for CLI use.
func ImportBase64URL(s string) ([]byte, error) {
	return decodeBase64URL(s)
}
