package k8sapilib

import (
	"net"
	"net/http"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	sdk "github.com/borderzero/border0-go/client"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var allowAllRule = sdk.KubernetesRule{
	APIGroups:     []string{"*"},
	Namespaces:    []string{"*"},
	Verbs:         []string{"*"},
	Resources:     []string{"*"},
	ResourceNames: []string{"*"},
}

func getAuthorizationDetails(
	logger *zap.Logger,
	evaluator k8sPolicyEvaluator,
	socket *border0.Socket,
	userEmail string,
	sessionID uuid.UUID,
	w http.ResponseWriter,
	r *http.Request,
) ([]sdk.KubernetesRule, bool) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logger.Error("failed to split remote address", zap.String("remote_addr", r.RemoteAddr), zap.Error(err))
		http.Error(w, "an unknown error occurred... try again later.", http.StatusInternalServerError)
		return nil, false
	}

	actions, _, err := evaluator.Evaluate(r.Context(), socket.Socket, clientIP, userEmail, sessionID.String())
	if err != nil {
		logger.Error(
			"failed to evaluate session against policy",
			zap.String("socket_id", socket.SocketID),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("client_ip", clientIP),
			zap.String("user_email", userEmail),
			zap.String("session_key", sessionID.String()),
			zap.Error(err),
		)
		http.Error(w, "an unknown error occurred... try again later.", http.StatusInternalServerError)
		return nil, false
	}

	allowed := false
	rules := []sdk.KubernetesRule{}
	for _, action := range actions {
		switch permission := action.(type) {
		case string:
			allowed = true
			rules = append(rules, allowAllRule)
		case models.Permissions:
			if permission.Kubernetes != nil {
				allowed = true
				if permission.Kubernetes.Rules != nil {
					rules = append(rules, *permission.Kubernetes.Rules...)
				} else {
					rules = append(rules, allowAllRule)
				}
			}
		}
	}
	if !allowed {
		http.Error(w, "no policy allows kubernetes access", http.StatusForbidden)
		return nil, false
	}

	return rules, allowed
}
