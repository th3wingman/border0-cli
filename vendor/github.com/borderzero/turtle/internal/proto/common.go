package proto

import (
	"errors"
	"io"
	"net"
	"strings"
)

func isDisconnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		strings.Contains(errStr, "websocket: close 1006 (abnormal closure): unexpected EOF") ||
		strings.Contains(errStr, "read: operation timed out") ||
		strings.Contains(errStr, "read: can't assign requested address") ||
		strings.Contains(errStr, "read: no route to host")
}
