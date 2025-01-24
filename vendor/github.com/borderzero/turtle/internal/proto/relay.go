package proto

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/turtle/internal/lib/connmap"
	"github.com/borderzero/turtle/internal/lib/gpool"
	"github.com/borderzero/turtle/internal/lib/keyconn"
	"github.com/borderzero/turtle/pkg/mesh"
	"github.com/cenkalti/backoff/v4"
	"github.com/coder/websocket"
	"github.com/pion/dtls/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	defaultClientEchoRequestInterval = time.Second * 10
	defaultRelayEchoRequestInterval  = time.Second * 10
)

type Relay struct {
	logger    *zap.Logger
	key       *nacl.PrivateKey
	nacl      nacl.Service
	localAddr net.Addr
	conns     connmap.ConnMap
	mesh      mesh.Mesh
	pbuffers  *gpool.Pool[[]byte] // buffer pool for reading inbound packets
	ctx       context.Context
	ctxc      context.CancelFunc

	clientEchoRequestInterval time.Duration
	relayEchoRequestInterval  time.Duration
}

func NewRelay(logger *zap.Logger, key *nacl.PrivateKey, mesh mesh.Mesh) (*Relay, error) {
	naclSvc, err := nacl.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize nacl service with the provided key: %v", err)
	}
	ctx, ctxc := context.WithCancel(context.Background())

	r := &Relay{
		logger:    logger,
		key:       key,
		nacl:      naclSvc,
		localAddr: AddrFromKey(key.Public()),
		conns:     connmap.New(),
		mesh:      mesh,
		pbuffers:  gpool.New[[]byte](func() []byte { return make([]byte, MaxPacketSize) }),
		ctx:       ctx,
		ctxc:      ctxc,

		clientEchoRequestInterval: defaultClientEchoRequestInterval,
		relayEchoRequestInterval:  defaultRelayEchoRequestInterval,
	}

	return r, nil
}

func (r *Relay) LocalAddr() net.Addr { return r.localAddr }

func (r *Relay) Close() { r.ctxc() }

func (r *Relay) Start() {
	for peerAddr, peerPub := range r.mesh.GetPeerDetails() {
		// highest alphanumeric key is the initiator
		if peerPub.B64() > r.key.Public().B64() {
			bo := backoff.NewExponentialBackOff(
				backoff.WithInitialInterval(2*time.Second), // wait for 2 seconds after first attempt
				backoff.WithMaxInterval(20*time.Second),    // wait for no more than 20 seconds between attempts
				backoff.WithMultiplier(1.5),                // increase interval by 1.5x after each failed attempt
				backoff.WithRandomizationFactor(0.2),       // jitter of 20% of the current interval
			)

			operation := func() error {
				parsedUrl, err := url.Parse(peerAddr)
				if err != nil {
					return backoff.Permanent(fmt.Errorf("failed to parse peer address as a url: %v", err))
				}

				select {
				case <-r.ctx.Done():
					return backoff.Permanent(r.ctx.Err())
				default:

					var conn net.Conn

					switch parsedUrl.Scheme {
					case "ws", "wss":
						websocketConn, _, err := websocket.Dial(r.ctx, peerAddr, nil)
						if err != nil {
							return fmt.Errorf("failed to dial peer with websocket address: %v", err)
						}
						conn = websocket.NetConn(r.ctx, websocketConn, websocket.MessageBinary)
					case "tcp":
						tcpAddr, err := net.ResolveTCPAddr("tcp", parsedUrl.Host)
						if err != nil {
							return fmt.Errorf("failed to resolve hostname for tcp address: %v", err)
						}
						tcpConn, err := net.DialTCP("tcp", &net.TCPAddr{}, tcpAddr)
						if err != nil {
							return fmt.Errorf("failed to dial peer with tcp address: %v", err)
						}
						conn = tcpConn
					case "tls":
						tlsAddr, err := net.ResolveTCPAddr("tcp", parsedUrl.Host)
						if err != nil {
							return fmt.Errorf("failed to resolve hostname for tls address: %v", err)
						}
						tlsConn, err := tls.Dial("tcp", tlsAddr.String(), r.mesh.GetTlsConfig())
						if err != nil {
							return fmt.Errorf("failed to dial peer with tls address: %v", err)
						}
						conn = tlsConn
					case "udp":
						udpAddr, err := net.ResolveUDPAddr("udp", parsedUrl.Host)
						if err != nil {
							return fmt.Errorf("failed to resolve hostname for udp address: %v", err)
						}
						udpConn, err := net.DialUDP("udp", &net.UDPAddr{}, udpAddr)
						if err != nil {
							return fmt.Errorf("failed to dial peer with udp address: %v", err)
						}
						conn = udpConn
					case "dtls":
						udpAddr, err := net.ResolveUDPAddr("udp", parsedUrl.Host)
						if err != nil {
							return fmt.Errorf("failed to resolve hostname for dtls (udp) address: %v", err)
						}
						tlsConfig := r.mesh.GetTlsConfig()
						dtlsConn, err := dtls.Dial("udp", udpAddr, &dtls.Config{
							// used for server to authenticate local peer
							Certificates: tlsConfig.Certificates,
							// used to authenticate remote peer
							InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
							RootCAs:            tlsConfig.RootCAs,
						})
						if err != nil {
							return fmt.Errorf("failed to dial peer with dtls address: %v", err)
						}
						conn = dtlsConn
					default:
						return backoff.Permanent(fmt.Errorf("peer address %s does not have a valid scheme (not [ws, wss, tcp, tls, udp, dtls])", peerAddr))
					}

					keyconn, err := Authenticate(conn, r.key)
					if err != nil {
						return fmt.Errorf("failed to authenticate peer websocket conn: %v", err)
					}
					bo.Reset()
					r.handleRelayConn(keyconn) // this blocks until there's an unrecoverable error.

					return fmt.Errorf("relay connection terminated")
				}
			}

			notify := func(err error, duration time.Duration) {
				r.logger.Debug(
					"failed to connect to peered-relay",
					zap.String("peered_relay_addr", peerAddr),
					zap.String("peered_relay_pub", peerPub.B64()),
					zap.Duration("next_retry_in", duration),
					zap.Duration("total_elapsed_time", bo.GetElapsedTime()),
					zap.Error(err),
				)
			}

			go func() {
				if err := backoff.RetryNotify(operation, backoff.WithContext(bo, r.ctx), notify); err != nil {
					r.logger.Error("permanent error during peer reconnection attempt, will not retry", zap.Error(err))
				}
			}()
		}
	}
}

func (r *Relay) HandleConn(conn net.Conn) {
	defer conn.Close()

	pub, err := r.authenticateClient(conn)
	if err != nil {
		r.logger.Error(
			"failed to authenticate TURTLE client connection",
			zap.Error(err),
		)
		return
	}

	if r.mesh.HasPeer(pub) {
		r.logger.Debug("peered-relay authenticated", zap.String("pub", pub.B64()))
		r.handleRelayConn(keyconn.NewKeyConn(pub, conn))
	} else {
		r.logger.Debug("client authenticated", zap.String("pub", pub.B64()))
		r.handleClientConn(keyconn.NewKeyConn(pub, conn))
	}
}

func (r *Relay) announceClientJoined(pub *nacl.PublicKey) {
	addrToPub := r.mesh.GetPeerDetails()
	for _, peerPub := range addrToPub {
		r.logger.Info(
			"announcing added client to peered-relay",
			zap.String("peered_relay_pub", peerPub.B64()),
			zap.String("client_pub", pub.B64()),
		)
		if conn, ok := r.conns.Get(AddrFromKey(peerPub)); ok {
			if err := sendAddedClient(conn, pub); err != nil {
				r.logger.Error(
					"failed to announce added client to peered-relay",
					zap.String("peered_relay_pub", peerPub.B64()),
					zap.String("client_pub", pub.B64()),
				)
				continue
			}
			r.logger.Info(
				"announced added client to peered-relay",
				zap.String("peered_relay_pub", peerPub.B64()),
				zap.String("client_pub", pub.B64()),
			)
		} else {
			r.logger.Warn("no conn available for peered-relay", zap.String("peered_relay_pub", peerPub.B64()))
		}
	}
}

func (r *Relay) announceClientDropped(pub *nacl.PublicKey) {
	addrToPub := r.mesh.GetPeerDetails()
	for _, peerPub := range addrToPub {
		r.logger.Info(
			"announcing removed client to peered-relay",
			zap.String("peered_relay_pub", peerPub.B64()),
			zap.String("client_pub", pub.B64()),
		)
		if conn, ok := r.conns.Get(AddrFromKey(peerPub)); ok {
			if err := sendRemovedClient(conn, pub); err != nil {
				r.logger.Error(
					"failed to announce removed client to peered-relay",
					zap.String("peer_pub", peerPub.B64()),
					zap.String("client_pub", pub.B64()),
				)
				continue
			}
			r.logger.Info(
				"announced removed client to peered-relay",
				zap.String("peered_relay_pub", peerPub.B64()),
				zap.String("client_pub", pub.B64()),
			)
		} else {
			r.logger.Warn("no conn available for peered-relay", zap.String("peered_relay_pub", peerPub.B64()))
		}
	}
}

func (r *Relay) handleRelayConn(conn *keyconn.KeyConn) {
	pub := conn.Key()
	srcConnAddr := AddrFromKey(pub)

	// before anything else we must share the current clients
	// held by this relay with the newly connected relay.
	if err := r.sendCurrentClients(conn); err != nil {
		r.logger.Error(
			"failed to share connected clients with peer",
			zap.String("pub", pub.B64()),
			zap.Error(err),
		)
		return
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		hbuf := make([]byte, maxHeaderSize)

		for {
			if err := r.handleRelayMessage(srcConnAddr, pub, conn, hbuf); err != nil {
				if !isDisconnectionError(err) {
					r.logger.Error(
						"non-recoverable error while reading packet from connection",
						zap.String("src_conn", srcConnAddr.String()),
						zap.Error(err),
					)
				}
				return
			}
		}
	}()

	r.conns.Set(srcConnAddr, conn)
	r.logger.Info("peered-relay connected", zap.String("pub", pub.B64()))

	defer func() {
		r.conns.ConditionallyDelete(srcConnAddr, func(kc *keyconn.KeyConn) bool { return kc.ID() == conn.ID() })
		r.logger.Info("peered-relay disconnected", zap.String("pub", pub.B64()))
		go r.mesh.RemoveRelayPeers(pub)
	}()

	for {
		select {
		case <-done:
			return
		case <-r.ctx.Done():
			return
		case <-time.After(r.relayEchoRequestInterval):
			if err := r.sendEchoRequest(conn); err != nil {
				r.logger.Warn("failed to send echo request", zap.Error(err))
			}
		}
	}
}

func (r *Relay) sendCurrentClients(conn *keyconn.KeyConn) error {
	clientPubs := r.conns.Keys()

	keysBuf := []byte{}
	for _, pub := range clientPubs {
		// only send public keys for clients (not relays)
		if !r.mesh.HasPeer(pub) {
			keysBuf = append(keysBuf, pub.Raw()[:]...)
		}
	}

	_, err := conn.WriteAll([][]byte{
		{messageTypeCurrentClients},
		binary.BigEndian.AppendUint32(nil, uint32(len(keysBuf)/nacl.KeyLength)), // number of keys as uint32
		keysBuf,
	})
	return err
}

func (r *Relay) sendEchoRequest(conn *keyconn.KeyConn) error {
	_, err := conn.Write([]byte{messageTypeEchoRequest})
	return err
}

func (r *Relay) handleClientConn(conn *keyconn.KeyConn) {
	pub := conn.Key()
	srcAddr := AddrFromKey(pub)

	r.conns.Set(srcAddr, conn)
	r.logger.Info("client connected", zap.String("pub", pub.B64()))

	done := make(chan struct{})

	go func() {
		defer close(done)

		hbuf := make([]byte, maxHeaderSize)

		for {
			if err := r.handleClientMessage(srcAddr, conn, hbuf); err != nil {
				if !isDisconnectionError(err) {
					r.logger.Error(
						"non-recoverable error while reading packet from connection",
						zap.String("src", srcAddr.String()),
						zap.Error(err),
					)
				}
				return
			}
		}
	}()

	go r.announceClientJoined(pub)

	defer func() {
		r.conns.ConditionallyDelete(srcAddr, func(kc *keyconn.KeyConn) bool { return kc.ID() == conn.ID() })
		r.logger.Info("client disconnected", zap.String("pub", pub.B64()))
		go r.announceClientDropped(pub)
	}()

	for {
		select {
		case <-done:
			return
		case <-r.ctx.Done():
			return
		case <-time.After(r.clientEchoRequestInterval):
			if err := r.sendEchoRequest(conn); err != nil {
				r.logger.Warn("failed to send echo request", zap.Error(err))
			}
		}
	}
}

// authenticateClient authenticates a newly accepted connection (i.e. performs
// the TURTLE authentication handshake).
func (r *Relay) authenticateClient(conn net.Conn) (*nacl.PublicKey, error) {
	clientHello, err := receiveClientHello(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive client hello message: %v", err)
	}
	pub := clientHello.PublicKey

	challenge, err := r.nacl.NewChallengeForPeer(pub)
	if err != nil {
		return pub, fmt.Errorf("failed to generate new auth challenge for client: %v", err)
	}
	chData, chNonce := challenge.ToSolve()

	if err := sendAuthChallenge(conn, chNonce, chData, r.key.Public()); err != nil {
		return pub, fmt.Errorf("failed to send auth challenge to client: %v", err)
	}

	solution, err := receiveAuthSolution(conn)
	if err != nil {
		return pub, fmt.Errorf("failed to receive auth challenge solution message: %v", err)
	}

	if !challenge.IsSolution(solution.SolutionData, solution.SolutionNonce) {
		return pub, errors.New("the provided solution is not a solution to the given challenge")
	}

	if err := sendClientAccepted(conn); err != nil {
		return pub, fmt.Errorf("failed to send client accepted message to client: %v", err)
	}

	return pub, nil
}

// handleRelayMessage handles a single message from another relay.
func (r *Relay) handleRelayMessage(
	srcConnAddr net.Addr,
	pub *nacl.PublicKey,
	conn *keyconn.KeyConn,
	hbuf []byte,
) error {
	if _, err := io.ReadFull(conn, hbuf[:messageTypeSize]); err != nil {
		return err
	}
	messageType := hbuf[0]

	switch messageType {
	case messageTypeEchoRequest:
		return r.handleEchoRequest(conn)
	case messageTypeEchoResponse:
		return r.handleEchoResponse()
	case messageTypeCurrentClients:
		return r.handleRelayCurrentClientsMessage(pub, conn, hbuf[messageTypeSize:])
	case messageTypeAddedClient:
		return r.handleRelayClientActionMessage(pub, conn, hbuf[messageTypeSize:], true)
	case messageTypeRemovedClient:
		return r.handleRelayClientActionMessage(pub, conn, hbuf[messageTypeSize:], false)
	case messageTypeXRelayedPacket:
		return r.handleXRelayedPacket(srcConnAddr, conn, hbuf[messageTypeSize:])
	default:
		return fmt.Errorf("unhandled message type %d", messageType)
	}
}

// handleClientMessage handles a single message from the client.
func (r *Relay) handleClientMessage(
	srcAddr net.Addr,
	srcConn *keyconn.KeyConn,
	hbuf []byte,
) error {
	if _, err := io.ReadFull(srcConn, hbuf[:messageTypeSize]); err != nil {
		return err
	}
	messageType := hbuf[0]

	switch messageType {
	case messageTypeEchoResponse:
		return r.handleEchoResponse()
	case messageTypePacket:
		return r.handlePacket(srcAddr, srcConn, hbuf[messageTypeSize:])
	default:
		return fmt.Errorf("unhandled message type %d", messageType)
	}
}

func (r *Relay) handleRelayCurrentClientsMessage(
	relayPub *nacl.PublicKey,
	srcConn *keyconn.KeyConn,
	hbuf []byte,
) error {
	uint32Bytes := 4
	// read the number of keys incoming
	if _, err := io.ReadFull(srcConn, hbuf[:uint32Bytes]); err != nil {
		return err
	}
	nKeys := binary.BigEndian.Uint32(hbuf[:uint32Bytes])

	// read all of the keys in one go
	rawKeysBuf := make([]byte, nKeys*nacl.KeyLength)
	if _, err := io.ReadFull(srcConn, rawKeysBuf); err != nil {
		return err
	}

	// process the keys
	clientPubs := make([]*nacl.PublicKey, nKeys)
	for i := uint32(0); i < nKeys; i++ {
		pub, err := nacl.ParsePublicKey(rawKeysBuf[i*nacl.KeyLength : (i+1)*nacl.KeyLength])
		if err != nil {
			return fmt.Errorf("failed to parse public key at index %d", i)
		}
		clientPubs[i] = pub
	}

	// add the keys to local records
	if err := r.mesh.AddClientsToRelay(relayPub, clientPubs...); err != nil {
		return fmt.Errorf("failed to add client pubs to local records: %v", err)
	}
	return nil
}

func (r *Relay) handleRelayClientActionMessage(
	relayPub *nacl.PublicKey,
	srcConn *keyconn.KeyConn,
	hbuf []byte,
	added bool,
) error {
	if _, err := io.ReadFull(srcConn, hbuf[:nacl.KeyLength]); err != nil {
		return err
	}
	clientPub, err := nacl.ParsePublicKey(hbuf[:nacl.KeyLength])
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}
	if added {
		r.logger.Info(
			"added client to relay",
			zap.String("peer_pub", relayPub.B64()),
			zap.String("client_pub", clientPub.B64()),
		)
		return r.mesh.AddClientsToRelay(relayPub, clientPub)
	}
	r.logger.Info(
		"removed client from relay",
		zap.String("peer_pub", relayPub.B64()),
		zap.String("client_pub", clientPub.B64()),
	)
	return r.mesh.RemoveClientFromRelay(relayPub, clientPub)
}

func (r *Relay) handlePacket(
	srcConnAddr net.Addr,
	conn *keyconn.KeyConn,
	hbuf []byte,
) error {
	// read the public key
	if _, err := io.ReadFull(conn, hbuf[:nacl.KeyLength]); err != nil {
		return err
	}
	toPub, err := nacl.ParsePublicKey(hbuf[:nacl.KeyLength])
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}
	dstAddr := AddrFromKey(toPub)
	hbuf = hbuf[nacl.KeyLength:]

	// read data length
	if _, err := io.ReadFull(conn, hbuf[:dataLenSize]); err != nil {
		return err
	}
	dataLen := binary.BigEndian.Uint16(hbuf[:dataLenSize])
	hbuf = hbuf[dataLenSize:]

	// grab a buffer from the pool to read the incoming packet,
	// and return it to the pool when done with it.
	pbuf := r.pbuffers.Get()
	defer r.pbuffers.Put(pbuf)

	// read the data
	if _, err = io.ReadFull(conn, pbuf[:int(dataLen)]); err != nil {
		return err
	}

	loggerOpts := []zapcore.Field{
		zap.String("src", srcConnAddr.String()),
		zap.String("dst", dstAddr.String()),
		zap.String("src_conn", srcConnAddr.String()),
	}

	// if we have a direct connection to the destination
	dstConn, ok := r.conns.Get(dstAddr)
	if ok {
		loggerOpts = append(loggerOpts, zap.String("dst_conn", dstAddr.String()))
		if err := sendRelayedPacket(dstConn, srcConnAddr, pbuf[:int(dataLen)]); err != nil {
			r.logger.Warn("failed to forward relayed packet", append(loggerOpts, zap.Error(err))...)
			return nil
		}
		r.logger.Debug("forwarded packet to client", loggerOpts...)
		return nil
	}

	// if we have a relayed connection to the destination
	nextHop, ok := r.mesh.GetRelayForClient(toPub)
	if ok {
		loggerOpts = append(loggerOpts, zap.String("dst_conn", nextHop.B64()))
		dstConn, ok = r.conns.Get(AddrFromKey(nextHop))
		if !ok {
			r.logger.Warn("destination relay for packet is not connected", loggerOpts...)
			return nil
		}
		if err := sendXRelayedPacket(dstConn, srcConnAddr, AddrFromKey(toPub), pbuf[:int(dataLen)]); err != nil {
			r.logger.Warn("failed to forward relayed packet", append(loggerOpts, zap.Error(err))...)
			return nil
		}
		r.logger.Debug("forwarded packet to relay", loggerOpts...)
		return nil
	}

	r.logger.Warn("destination for packet is not connected", loggerOpts...)
	return nil
}

func (r *Relay) handleXRelayedPacket(
	srcConnAddr net.Addr,
	srcConn *keyconn.KeyConn,
	hbuf []byte,
) error {
	// read the from public key
	if _, err := io.ReadFull(srcConn, hbuf[:nacl.KeyLength]); err != nil {
		return err
	}
	fromPub, err := nacl.ParsePublicKey(hbuf[:nacl.KeyLength])
	if err != nil {
		return fmt.Errorf("failed to parse FROM public key: %v", err)
	}
	hbuf = hbuf[nacl.KeyLength:]

	// read the to public key
	if _, err := io.ReadFull(srcConn, hbuf[:nacl.KeyLength]); err != nil {
		return err
	}
	toPub, err := nacl.ParsePublicKey(hbuf[:nacl.KeyLength])
	if err != nil {
		return fmt.Errorf("failed to parse TO public key: %v", err)
	}
	hbuf = hbuf[nacl.KeyLength:]

	// read data length
	if _, err := io.ReadFull(srcConn, hbuf[:dataLenSize]); err != nil {
		return err
	}
	dataLen := binary.BigEndian.Uint16(hbuf[:dataLenSize])
	hbuf = hbuf[dataLenSize:]

	// grab a buffer from the pool to read the incoming packet,
	// and return it to the pool when done with it.
	pbuf := r.pbuffers.Get()
	defer r.pbuffers.Put(pbuf)

	// read the data
	if _, err = io.ReadFull(srcConn, pbuf[:int(dataLen)]); err != nil {
		return err
	}

	srcAddr := AddrFromKey(fromPub)
	dstAddr := AddrFromKey(toPub)

	loggerOpts := []zapcore.Field{
		zap.String("src", srcAddr.String()),
		zap.String("dst", dstAddr.String()),
		zap.String("src_conn", srcConnAddr.String()),
	}

	// if we have a direct connection to the destination
	dstConn, ok := r.conns.Get(dstAddr)
	if ok {
		loggerOpts = append(loggerOpts, zap.String("dst_conn", dstAddr.String()))
		if err := sendRelayedPacket(dstConn, srcAddr, pbuf[:int(dataLen)]); err != nil {
			r.logger.Warn("failed to forward relayed packet", append(loggerOpts, zap.Error(err))...)
			return nil
		}
		r.logger.Debug("forwarded packet to client", loggerOpts...)
		return nil
	}

	// NOTE: messages from other relays MUST be for a destination attached to *THIS* relay.
	// Multiple relay hops are NOT supported. This is to avoid routing loops at all costs.
	// We also do not support announcing other relay's clients (e.g. BGP does), so it will
	// never be the case that a message from a relay is for an address that is held by a
	// different relay.

	r.logger.Warn("destination for packet is not connected", loggerOpts...)
	return nil
}

func (r *Relay) handleEchoRequest(srcConn *keyconn.KeyConn) error {
	_, err := srcConn.Write([]byte{messageTypeEchoResponse})
	return err
}

func (r *Relay) handleEchoResponse() error {
	// TODO(@adriano): do something here? e.g. reset keep alive logic? (this does not exist yet.)
	r.logger.Debug("got echo response message")
	return nil
}
