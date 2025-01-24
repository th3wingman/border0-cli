//go:build !js

package wsdialopts

import (
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// GetDialOpts returns the websocket dial options.
func GetDialOpts(timeout time.Duration) *websocket.DialOptions {
	return &websocket.DialOptions{
		HTTPClient: &http.Client{Timeout: timeout},
	}
}
