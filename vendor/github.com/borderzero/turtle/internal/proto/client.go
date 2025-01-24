package proto

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/turtle/internal/lib/gpool"
	"github.com/borderzero/turtle/internal/lib/keyconn"
	"go.uber.org/zap"
)

// InboundPacket represents a single inbound data packet.
type InboundPacket struct {
	From   net.Addr
	N      int
	Buffer []byte
}

// Authenticate authenticates a connection against the remote relay server.
func Authenticate(conn net.Conn, priv *nacl.PrivateKey) (*keyconn.KeyConn, error) {
	if err := sendClientHello(conn, priv.Public()); err != nil {
		return nil, fmt.Errorf("failed to send client hello message to TURTLE server: %v", err)
	}
	challenge, err := receiveAuthChallenge(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive auth challenge message from TURTLE server: %v", err)
	}
	soln, nonce, err := nacl.SolveChallenge(challenge.ChallengeData, challenge.ChallengeNonce, challenge.ServerPublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to solve TURTLE server authentication challenge: %v", err)
	}
	if err := sendAuthSolution(conn, nonce, soln); err != nil {
		return nil, fmt.Errorf("failed to send auth challenge solution message to TURTLE server: %v", err)
	}
	if _, err := receiveClientAccepted(conn); err != nil {
		return nil, fmt.Errorf("failed to receive client accepted message from TURTLE server: %v", err)
	}
	return keyconn.NewKeyConn(challenge.ServerPublicKey, conn), nil
}

func DeliverPackets(
	ctx context.Context,
	logger *zap.Logger,
	connptr *atomic.Pointer[keyconn.KeyConn],
	rxPackets chan *InboundPacket,
	rxPacketBufferPool *gpool.Pool[[]byte],
	reconnect func(),
) {
	defer close(rxPackets)

	// re-usable buffer for reading headers
	headerBuffer := make([]byte, maxHeaderSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := handleServerMessage(connptr, headerBuffer, rxPackets, rxPacketBufferPool); err != nil {
				if isDisconnectionError(err) {
					reconnect()
					continue
				}
				if errors.Is(err, context.Canceled) {
					logger.Info("relay client context cancelled, exiting")
					return
				}
				logger.Error("unrecoverable error while handling server message", zap.Error(err))
				return
			}
		}
	}
}

// handleServerMessage handles a single message from the server.
func handleServerMessage(
	connptr *atomic.Pointer[keyconn.KeyConn],
	hbuf []byte,
	rxPackets chan *InboundPacket,
	rxPacketBufferPool *gpool.Pool[[]byte],
) error {
	hoffset := 0

	conn := connptr.Load()
	if conn == nil {
		return net.ErrClosed
	}

	// read the message type
	if _, err := io.ReadFull(conn, hbuf[:messageTypeSize]); err != nil {
		return err
	}
	messageType := hbuf[0]
	hoffset += messageTypeSize

	switch messageType {
	case messageTypeRelayedPacket:
		return handleRelayedPacket(conn, hoffset, hbuf, rxPackets, rxPacketBufferPool)
	case messageTypeEchoRequest:
		return handleEcho(conn)
	default:
		return fmt.Errorf("unhandled message type %d", messageType)
	}
}

// handleRelayedPacket handles a message of type messageTypeRelayedPacket.
func handleRelayedPacket(
	r io.Reader,
	hoffset int,
	hbuf []byte,
	rxPackets chan *InboundPacket,
	pbufpool *gpool.Pool[[]byte],
) error {
	// read the public key
	if _, err := io.ReadFull(r, hbuf[hoffset:hoffset+nacl.KeyLength]); err != nil {
		return err
	}
	pub, err := nacl.ParsePublicKey(hbuf[hoffset : hoffset+nacl.KeyLength])
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}
	hoffset += nacl.KeyLength

	// read data length
	if _, err := io.ReadFull(r, hbuf[hoffset:hoffset+dataLenSize]); err != nil {
		return err
	}
	dataLen := binary.BigEndian.Uint16(hbuf[hoffset : hoffset+dataLenSize])
	hoffset += dataLenSize

	// get an available buffer from buffer pool
	pbuf := pbufpool.Get()

	// read the data
	n, err := io.ReadFull(r, pbuf[:dataLen])
	if err != nil {
		return err
	}

	// send read packet to channel
	rxPackets <- &InboundPacket{
		From:   AddrFromKey(pub),
		N:      n,
		Buffer: pbuf,
	}

	return nil
}

// handleEcho handles a message of type messageTypeEcho.
func handleEcho(
	w io.Writer,
) error {
	if _, err := w.Write([]byte{messageTypeEchoResponse}); err != nil {
		return fmt.Errorf("failed to write message type byte: %v", err)
	}
	return nil
}
