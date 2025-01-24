package keyconn

import (
	"net"
	"sync"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/google/uuid"
)

// KeyConn is our custom net.Conn wrapper.
//
// Today it serves two purposes:
// (1) It ensures that multiple-buffer writes to net.Conn are
// concurrency-safe. This is useful because writing multiple
// buffers instead of appending the multiple buffers into a
// single one does not require allocating new memory to hold
// the resulting buffer.
// (2) It associates an public key with a connection. All
// instances of KeyConn are authenticated connections, where
// you can trust that all messages read come from the holder
// of the private key for the public key returned by Key().
type KeyConn struct {
	// Note: normally, embedding structs directly is discouraged due to method
	// shadowing and the complexity it introduces, but, given the small and
	// specific purpose of this package, we accept this design for simplicity.
	net.Conn

	id        string
	pub       *nacl.PublicKey
	writeLock sync.Mutex
}

// NewKeyConn returns a new KeyConn.
func NewKeyConn(pub *nacl.PublicKey, conn net.Conn) *KeyConn {
	return &KeyConn{Conn: conn, id: uuid.NewString(), pub: pub}
}

// ID returns the connection's unique identifier. This is used
// to ensure we don't wipe out connections from the server's
// connection mapping unintentionally when facing rapid client
// disconnections/reconnections.
func (kc *KeyConn) ID() string { return kc.id }

// Key gets the public key for the KeyConn.
func (kc *KeyConn) Key() *nacl.PublicKey { return kc.pub }

// Write writes data to the connection with concurrency protection.
// Note: this method overrides Write() on the embedded net.Conn.
func (kc *KeyConn) Write(b []byte) (int, error) {
	kc.writeLock.Lock()
	defer kc.writeLock.Unlock()

	return kc.Conn.Write(b)
}

// WriteAll writes multiple slices to the connection with concurrency protection.
func (kc *KeyConn) WriteAll(bs [][]byte) (int, error) {
	kc.writeLock.Lock()
	defer kc.writeLock.Unlock()

	nsum := 0
	for _, b := range bs {
		n, err := kc.Conn.Write(b)
		nsum += n
		if err != nil {
			return nsum, err
		}
	}

	return nsum, nil
}
