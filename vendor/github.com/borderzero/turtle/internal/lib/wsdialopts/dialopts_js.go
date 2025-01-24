//go:build js

package wsdialopts

import (
	"time"

	"github.com/coder/websocket"
)

// GetDialOpts returns the websocket dial options.
func GetDialOpts(_ time.Duration) *websocket.DialOptions {
	return &websocket.DialOptions{ /* NO-OP */ }
}
