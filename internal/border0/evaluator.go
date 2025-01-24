package border0

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	gcache "github.com/Code-Hex/go-generics-cache"
	"github.com/borderzero/border0-cli/internal/api/models"
)

type policyEvaluator interface {
	Evaluate(ctx context.Context, socket *models.Socket, clientIP, userEmail, sessionKey string) (allowedActions []any, info map[string][]string, err error)
	EvaluatePeer(ctx context.Context, socket *models.Socket, clientAddr *net.TCPAddr, clientIP, publicKey, sessionKey string) (string, string, string, []byte, []any, error)
}

// cachedPolicyEvaluator is an implementation of cachedPolicyEvaluator
// which caches results for a given duration. This is useful to prevent
// the connector from hammering the API with evaluation requests. Hitting
// this rate limit could be particularly common when clients are using
// clients which perform actions on their behalf such as Lens, k9s, etc.
type cachedPolicyEvaluator struct {
	api             Border0API
	policyCache     *gcache.Cache[string, cacheEntry]
	sessionCache    *gcache.Cache[string, string]
	policyCacheTTL  time.Duration
	sessionCacheTTL time.Duration
}

type cacheEntry struct {
	actions    []any
	email      string
	entityUUID string
	sessionID  string
}

func newCachedPolicyEvaluator(api Border0API, cacheJanitorInterval, policyCacheTTL time.Duration, sessionCacheTTL time.Duration) policyEvaluator {
	return &cachedPolicyEvaluator{
		api:             api,
		policyCache:     gcache.New[string, cacheEntry](gcache.WithJanitorInterval[string, cacheEntry](cacheJanitorInterval)),
		sessionCache:    gcache.New[string, string](gcache.WithJanitorInterval[string, string](cacheJanitorInterval)),
		policyCacheTTL:  policyCacheTTL,
		sessionCacheTTL: sessionCacheTTL,
	}
}

// Evaluate returns cached results if available, otherwise fresh
// results, saving them in the cache prior to returning.
func (e *cachedPolicyEvaluator) EvaluatePeer(
	ctx context.Context,
	socket *models.Socket,
	clientAddr *net.TCPAddr, clientIP, publicKey, sessionKey string,
) (string, string, string, []byte, []any, error) {
	key := fmt.Sprintf("%s-%s-%s", socket.SocketID, clientAddr.IP.String(), sessionKey)

	if sessionKey != "" {
		if ce, ok := e.policyCache.Get(key); ok {
			return ce.email, ce.entityUUID, ce.sessionID, nil, ce.actions, nil
		}
	}

	email, entityUUID, actions, authInfo, err := e.api.EvaluatePeer(ctx, socket, clientIP, publicKey)
	if err != nil {
		return "", "", "", nil, nil, err
	}

	if sessionKey != "" {
		if sessionID, ok := e.sessionCache.Get(key); ok {
			e.policyCache.Set(key, cacheEntry{actions: actions, email: email, entityUUID: entityUUID, sessionID: sessionID}, gcache.WithExpiration(e.policyCacheTTL))
			return email, entityUUID, sessionID, nil, actions, nil
		}
	}

	result, err := e.createSession(socket, email, entityUUID, clientAddr, clientIP, publicKey, actions, authInfo)
	if err != nil {
		return "", "", "", nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	e.policyCache.Set(key, cacheEntry{actions: actions, email: email, entityUUID: entityUUID, sessionID: result.SessionKey}, gcache.WithExpiration(e.policyCacheTTL))
	e.sessionCache.Set(key, result.SessionKey, gcache.WithExpiration(e.sessionCacheTTL))
	return email, entityUUID, result.SessionKey, result.SshTicket, actions, nil
}

func (e *cachedPolicyEvaluator) Evaluate(
	ctx context.Context,
	socket *models.Socket,
	clientIP, userEmail, sessionKey string,
) ([]any, map[string][]string, error) {
	key := fmt.Sprintf("%s-%s-%s-%s", socket.SocketID, clientIP, userEmail, sessionKey)

	if sessionKey == "" {
		return nil, nil, fmt.Errorf("session key is required")
	}

	if ce, ok := e.policyCache.Get(key); ok {
		return ce.actions, nil, nil
	}

	actions, authInfo, err := e.api.Evaluate(ctx, socket, clientIP, userEmail, sessionKey)
	if err != nil {
		return nil, nil, err
	}

	e.policyCache.Set(key, cacheEntry{actions: actions, email: userEmail, sessionID: sessionKey}, gcache.WithExpiration(e.policyCacheTTL))
	return actions, authInfo, nil
}

func deterministicUUIDv4(values ...string) uuid.UUID {
	hasher := sha256.New()
	for _, v := range values {
		hasher.Write([]byte(v))
	}
	hash := hasher.Sum(nil)
	uuidBytes := make([]byte, 16)
	copy(uuidBytes, hash[:16])
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40 // Version 4
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80 // Variant 10
	return uuid.UUID(uuidBytes)
}

// createSession creates a session for a given email, TCP address, action, and auth info.
func (e *cachedPolicyEvaluator) createSession(socket *models.Socket, email, entityUUID string, tcpAddr *net.TCPAddr, remoteIP, publicKey string, action []any, authInfo map[string][]string) (*models.SessionCreateResult, error) {
	var result string
	if len(action) == 0 {
		result = "denied"
	} else {
		result = "success"
	}
	authInfoEncoded, _ := json.Marshal(authInfo)

	metadataEncoded, _ := json.Marshal(map[string]map[string]string{
		"device": {
			"client_ip":  tcpAddr.IP.String(),
			"public_key": publicKey,
		},
	})

	session := models.Session{
		Email:      email,
		LogType:    strings.ToUpper(socket.SocketType),
		SocketID:   socket.SocketID,
		ServerName: socket.Name,
		ServerPort: strconv.Itoa(socket.TargetPort),
		ClientIP:   remoteIP,
		ClientPort: strconv.Itoa(tcpAddr.Port),
		Result:     result,
		AuthInfo:   string(authInfoEncoded),
		Metadata:   metadataEncoded,
		EntityUUID: entityUUID,
	}

	sessionResult, err := e.api.CreateSession(session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return sessionResult, nil
}
