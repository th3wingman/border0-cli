package k8sapilib

import (
	"context"
	"net/http"
	"time"
)

// custom context key type.
type kubernetesHttpRequestContextKey string

const (
	// context key for the received at timestamp.
	receivedAtContextKey kubernetesHttpRequestContextKey = "received_at"
	// context key for the connection.
	connContextKey kubernetesHttpRequestContextKey = "connection"
)

// sets the receivedAtContextKey in an http request's context.
func withReceivedAt(r *http.Request, receivedAt time.Time) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), receivedAtContextKey, receivedAt))
}

// gets the value for the receivedAtContextKey from an http request's context.
func getReceivedAt(r *http.Request) *time.Time {
	if r != nil {
		if value := r.Context().Value(receivedAtContextKey); value != nil {
			if timeValue, ok := value.(time.Time); ok {
				return &timeValue
			}
		}
	}
	return nil
}
