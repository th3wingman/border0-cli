package common

import "encoding/binary"

// ParseDims parses a message as width and height dimensions (4 bytes each).
func ParseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}
