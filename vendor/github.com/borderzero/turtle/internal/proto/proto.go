package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/turtle/internal/lib/keyconn"
)

const (
	// 0x01 - 0x1F: authentication
	messageTypeClientHello    = byte(0x01)
	messageTypeAuthChallenge  = byte(0x02)
	messageTypeAuthSolution   = byte(0x03)
	messageTypeClientAccepted = byte(0x04)

	// 0x21 - 0x3F: connection lifecycle management
	messageTypeEchoRequest  = byte(0x21)
	messageTypeEchoResponse = byte(0x22)

	// 0x41 - 0x5F: peers/route management
	messageTypeCurrentClients = byte(0x41)
	messageTypeAddedClient    = byte(0x42)
	messageTypeRemovedClient  = byte(0x43)

	// 0x61 - 0x7F: data
	messageTypePacket         = byte(0x61)
	messageTypeRelayedPacket  = byte(0x62)
	messageTypeXRelayedPacket = byte(0x63)
)

const (
	// messageTypeSize is the number of bytes in the TURTLE header used
	// to indicate the message type currently being read (1 B).
	messageTypeSize = 1

	// keySize is the number of bytes of a TURTLE (Noise / WireGuard) key (32 B).
	keySize = nacl.KeyLength

	// dataLenSize is the number of bytes in the TURTLE header used to indicate
	// the length of the data in the message. This value is communicated as a
	// uint16 in "big endian" format (2 B).
	dataLenSize = 2

	// maxHeaderSize is the maximum size in bytes that the TURTLE header may have.
	maxHeaderSize = messageTypeSize + (2 * keySize) + dataLenSize

	// MaxUdpPacketSize is the maximum size in bytes that a UDP packet may have.
	// This is one byte less than 64 KB = 64 KB - 1 = 65,535 B.
	MaxUdpPacketSize = 64<<10 - 1

	// MaxPacketSize is the maximum size in bytes that a TURTLE message may have.
	// This is equivalent to the maximum size of a TURTLE header plus the maximum
	// size of a data message payload.
	MaxPacketSize = maxHeaderSize + MaxUdpPacketSize
)

// clientHelloMessage represents the client-to-server "client
// hello" message. This type of message is the first message
// in the authentication handshake, where the client presents
// their public key.
type clientHelloMessage struct {
	PublicKey *nacl.PublicKey
}

// AuthChallengeMessage represents the server-to-client
// authentication challenge message. This type of message is
// the second message in the authentication handshake, where
// the server provides random data encrypted with the client's
// public key, along with a nonce used in the encryption. The
// server's public key is also sent so that the client encrypts
// the message back for the server (that step adds no security).
type AuthChallengeMessage struct {
	ChallengeNonce  nacl.Nonce
	ChallengeData   []byte
	ServerPublicKey *nacl.PublicKey
}

// AuthSolutionMessage represents the client-to-server
// authentication solution message. This type of message is
// the third message in the authentication handshake, where the
// client provides the solution to the cryptographic challenge
// sent by the server in the previous message. Since the solution
// data is encrypted for the server, the nonce used in the
// encryption is also included.
type AuthSolutionMessage struct {
	SolutionNonce nacl.Nonce
	SolutionData  []byte
}

// ClientAcceptedMessage represents the server-to-client
// "client accepted" message. This message is the fourth (and
// final) message in the authentication handshake, where the
// server lets the client know that it has been accepted.
type ClientAcceptedMessage struct{}

// sendClientHello sends a client hello message.
func sendClientHello(w io.Writer, pub *nacl.PublicKey) error {
	if _, err := w.Write([]byte{messageTypeClientHello}); err != nil {
		return err
	}
	_, err := w.Write(pub.Raw()[:])
	return err
}

// receiveClientHello receives a "client hello" message.
func receiveClientHello(r io.Reader) (*clientHelloMessage, error) {
	messageType := make([]byte, 1)
	if _, err := r.Read(messageType); err != nil {
		return nil, err
	}
	if messageType[0] != messageTypeClientHello {
		return nil, errors.New("incorrect message type for ClientHello")
	}
	pubBytes := make([]byte, nacl.KeyLength)
	if _, err := io.ReadFull(r, pubBytes); err != nil {
		return nil, err
	}
	pub, err := nacl.ParsePublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse received public key bytes: %v", err)
	}
	return &clientHelloMessage{PublicKey: pub}, nil
}

// sendAuthChallenge sends an authentication challenge message.
func sendAuthChallenge(w io.Writer, nonce nacl.Nonce, challenge []byte, pub *nacl.PublicKey) error {
	if _, err := w.Write([]byte{messageTypeAuthChallenge}); err != nil {
		return err
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return err
	}
	if _, err := w.Write([]byte{byte(len(challenge))}); err != nil {
		return err
	}
	if _, err := w.Write(challenge); err != nil {
		return err
	}
	_, err := w.Write(pub.Raw()[:])
	return err
}

// receiveAuthChallenge receives a authentication challenge message.
func receiveAuthChallenge(r io.Reader) (*AuthChallengeMessage, error) {
	messageType := make([]byte, 1)
	if _, err := r.Read(messageType); err != nil {
		return nil, err
	}
	if messageType[0] != messageTypeAuthChallenge {
		return nil, errors.New("incorrect message type for AuthChallenge")
	}
	nonce := new([nacl.NonceLength]byte)
	if _, err := io.ReadFull(r, nonce[:]); err != nil {
		return nil, err
	}
	var length byte
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	challengeData := make([]byte, length)
	if _, err := io.ReadFull(r, challengeData); err != nil {
		return nil, err
	}
	pubBytes := make([]byte, nacl.KeyLength)
	if _, err := io.ReadFull(r, pubBytes); err != nil {
		return nil, err
	}
	pub, err := nacl.ParsePublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse received public key bytes: %v", err)
	}
	return &AuthChallengeMessage{ChallengeNonce: nonce, ChallengeData: challengeData, ServerPublicKey: pub}, nil
}

// sendAuthSolution sends a authentication challenge solution message.
func sendAuthSolution(w io.Writer, nonce nacl.Nonce, soln []byte) error {
	if _, err := w.Write([]byte{messageTypeAuthSolution}); err != nil {
		return err
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return err
	}
	if _, err := w.Write([]byte{byte(len(soln))}); err != nil {
		return err
	}
	_, err := w.Write(soln)
	return err
}

// receiveAuthSolution receives an authentication challenge solution message.
func receiveAuthSolution(r io.Reader) (*AuthSolutionMessage, error) {
	messageType := make([]byte, 1)
	if _, err := r.Read(messageType); err != nil {
		return nil, err
	}
	if messageType[0] != messageTypeAuthSolution {
		return nil, errors.New("incorrect message type for AuthSolution")
	}
	nonce := new([nacl.NonceLength]byte)
	if _, err := io.ReadFull(r, nonce[:]); err != nil {
		return nil, err
	}
	var length byte
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	solutionData := make([]byte, length)
	if _, err := io.ReadFull(r, solutionData); err != nil {
		return nil, err
	}
	return &AuthSolutionMessage{SolutionNonce: nonce, SolutionData: solutionData}, nil
}

// sendClientAccepted sends a "client accepted" message.
func sendClientAccepted(w io.Writer) error {
	if _, err := w.Write([]byte{messageTypeClientAccepted}); err != nil {
		return err
	}
	return nil
}

// receiveClientAccepted receives a "client accepted" message.
func receiveClientAccepted(r io.Reader) (*ClientAcceptedMessage, error) {
	messageType := make([]byte, 1)
	if _, err := r.Read(messageType); err != nil {
		return nil, err
	}
	if messageType[0] != messageTypeClientAccepted {
		return nil, errors.New("incorrect message type for ClientAccepted")
	}
	return &ClientAcceptedMessage{}, nil
}

// SendPacket sends a packet message.
func SendPacket(dstConn *keyconn.KeyConn, data []byte, forAddr net.Addr) error {
	turtleAddr, ok := forAddr.(*address)
	if !ok {
		return fmt.Errorf("concrete type of forAddr is not a turtle address, got %T", forAddr)
	}
	if _, err := dstConn.WriteAll([][]byte{
		{messageTypePacket},
		turtleAddr.key.Raw()[:],
		binary.BigEndian.AppendUint16(nil, uint16(len(data))),
		data,
	}); err != nil {
		return fmt.Errorf("failed to write packet bytes to connection: %v", err)
	}
	return nil
}

// sendRelayedPacket sends a relayed packet message.
func sendRelayedPacket(dstConn *keyconn.KeyConn, connAddr net.Addr, data []byte) error {
	turtleConnAddr, ok := connAddr.(*address)
	if !ok {
		return fmt.Errorf("concrete type of connAddr is not a turtle address, got %T", connAddr)
	}
	if _, err := dstConn.WriteAll([][]byte{
		{messageTypeRelayedPacket},
		turtleConnAddr.key.Raw()[:],
		binary.BigEndian.AppendUint16(nil, uint16(len(data))),
		data,
	}); err != nil {
		return fmt.Errorf("failed to write message: %v", err)
	}
	return nil
}

// sendXRelayedPacket sends a cross-relayed packet message.
func sendXRelayedPacket(
	dstConn *keyconn.KeyConn,
	fromAddr net.Addr,
	toAddr net.Addr,
	data []byte,
) error {
	turtleFromAddr, ok := fromAddr.(*address)
	if !ok {
		return fmt.Errorf("concrete type of fromAddr is not a turtle address, got %T", fromAddr)
	}
	turtleToAddr, ok := toAddr.(*address)
	if !ok {
		return fmt.Errorf("concrete type of toAddr is not a turtle address, got %T", toAddr)
	}
	if _, err := dstConn.WriteAll([][]byte{
		{messageTypeXRelayedPacket},
		turtleFromAddr.key.Raw()[:],
		turtleToAddr.key.Raw()[:],
		binary.BigEndian.AppendUint16(nil, uint16(len(data))),
		data,
	}); err != nil {
		return fmt.Errorf("failed to write message: %v", err)
	}
	return nil
}

// sendAddedClient sends an added-client message.
func sendAddedClient(dstConn *keyconn.KeyConn, clientKey *nacl.PublicKey) error {
	if _, err := dstConn.WriteAll([][]byte{
		{messageTypeAddedClient},
		clientKey.Raw()[:],
	}); err != nil {
		return fmt.Errorf("failed to write message: %v", err)
	}
	return nil
}

// sendRemovedClient sends a removed-client message.
func sendRemovedClient(dstConn *keyconn.KeyConn, clientKey *nacl.PublicKey) error {
	if _, err := dstConn.WriteAll([][]byte{
		{messageTypeRemovedClient},
		clientKey.Raw()[:],
	}); err != nil {
		return fmt.Errorf("failed to write message: %v", err)
	}
	return nil
}

// ReceiveRelayedPacket receives a relayed packet message.
func ReceiveRelayedPacket(r io.Reader, hbuf, pbuf []byte) (int, net.Addr, error) {
	offset := 0

	// read the message type
	if _, err := io.ReadFull(r, hbuf[:messageTypeSize]); err != nil {
		return 0, nil, err
	}
	if hbuf[0] != messageTypeRelayedPacket {
		return 0, nil, fmt.Errorf("incorrect message type for Packet, expected %d but got %d", messageTypeRelayedPacket, hbuf[0])
	}
	offset += messageTypeSize

	// read the public key
	if _, err := io.ReadFull(r, hbuf[offset:offset+nacl.KeyLength]); err != nil {
		return 0, nil, err
	}
	pub, err := nacl.ParsePublicKey(hbuf[offset : offset+nacl.KeyLength])
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	addr := AddrFromKey(pub)
	offset += nacl.KeyLength

	// read data length
	if _, err := io.ReadFull(r, hbuf[offset:offset+dataLenSize]); err != nil {
		return 0, addr, err
	}
	dataLen := binary.BigEndian.Uint16(hbuf[offset : offset+dataLenSize])
	offset += dataLenSize

	// read the data
	n, err := io.ReadFull(r, pbuf[:dataLen])
	if err != nil {
		return 0, addr, err
	}
	return n, addr, nil
}
