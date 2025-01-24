package k8sapilib

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	sdk "github.com/borderzero/border0-go/client"
	"github.com/borderzero/border0-go/lib/types/slice"
	"github.com/borderzero/border0-go/lib/types/syncmap"
	"github.com/borderzero/border0-go/lib/types/wildcard"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type kubernetesRequest struct {
	verb         string
	apigroup     string
	namespace    string
	resource     string
	resourceName string
}

var unconditionalAllowPaths = []string{}

func evaluateAccess(
	logger *zap.Logger,
	api border0.Border0API,
	recorders *syncmap.Map[string, *expiringRecorder],
	socket *border0.Socket,
	sessionID uuid.UUID,
	rules []sdk.KubernetesRule,
	r *http.Request,
) error {
	if slices.Contains(unconditionalAllowPaths, r.URL.Path) {
		return nil
	}

	kubernetesRequest, err := kubernetesRequestFromHTTPRequest(r)
	if err != nil {
		return fmt.Errorf("failed to parse requested kubernetes resource from http request: %v", err)
	}

	// evaluate kubernetes requests against rules, stopping at first pass
	for _, rule := range rules {
		if evaluateRule(rule, kubernetesRequest) {
			return nil
		}
	}

	// build authz failure message
	deniedMsg := fmt.Sprintf("no policy rule allows access for verb \"%s\"", kubernetesRequest.verb)
	if kubernetesRequest.apigroup != "" {
		deniedMsg = fmt.Sprintf("%s, api group \"%s\"", deniedMsg, kubernetesRequest.apigroup)
	}
	deniedMsg = fmt.Sprintf("%s, resource type \"%s\"", deniedMsg, kubernetesRequest.resource)
	if kubernetesRequest.resourceName != "" {
		deniedMsg = fmt.Sprintf("%s, resource name \"%s\"", deniedMsg, kubernetesRequest.resourceName)
	}
	if kubernetesRequest.namespace != "" {
		if kubernetesRequest.namespace == "*" {
			deniedMsg = fmt.Sprintf("%s in all namespaces", deniedMsg)
		} else {
			deniedMsg = fmt.Sprintf("%s in the \"%s\" namespace", deniedMsg, kubernetesRequest.namespace)
		}
	}

	// record authz failure
	recordOne(logger, api, recorders, socket.Socket, sessionID, kubernetesRequest, getReceivedAt(r), http.StatusForbidden, deniedMsg)

	// emit event
	go func() {
		metadataBytes, err := json.Marshal(struct {
			Info string `json:"info"`
		}{Info: deniedMsg})
		if err != nil {
			logger.Error(
				"failed to JSON-encode metadata for kuberntes socket event",
				zap.String("socket_id", socket.SocketID),
				zap.Error(err),
			)
			return
		}
		if err := api.CreateSessionEvent(models.SessionEvent{
			SessionKey: sessionID.String(),
			Socket:     socket.Socket,
			Type:       "kubernetes_api_request",
			Status:     "denied",
			Metadata:   string(metadataBytes),
		}); err != nil {
			logger.Error(
				"failed to create denied request event for kuberntes socket",
				zap.String("socket_id", socket.SocketID),
				zap.Error(err),
			)
		}
	}()

	return errors.New(deniedMsg)
}

// Determines the kubernetes request attributes from an HTTP request.
//
// For inspiration see:
// - https://github.com/kubernetes/apiserver/blob/0d67427d5e9226bc1a0a2f1f52236c1a7c1e7a71/pkg/admission/interfaces.go#L31
// - https://github.com/kubernetes/apiserver/blob/0d67427d5e9226bc1a0a2f1f52236c1a7c1e7a71/pkg/audit/policy/checker.go#L64
func kubernetesRequestFromHTTPRequest(r *http.Request) (*kubernetesRequest, error) {
	kr := &kubernetesRequest{}

	parts := strings.Split(r.URL.Path, "/")

	// handle apigroup, namespace, resource, and resourceName
	if len(parts) > 1 && parts[1] == "apis" && len(parts) > 2 {
		kr.apigroup = parts[2]
		if len(parts) > 4 {
			if len(parts) > 6 && parts[4] == "namespaces" { // namespace scoped resources
				kr.namespace = parts[5]
				kr.resource = parts[6]
				if len(parts) > 7 {
					kr.resourceName = parts[7]
				}
			} else { // cluster scoped resources or all-namespaces
				kr.namespace = ""
				kr.resource = parts[4]
				if len(parts) > 5 { // specific namespace
					kr.resourceName = parts[5]
				}
			}
		}
	} else if len(parts) > 2 && parts[1] == "api" {
		kr.apigroup = "" // core API group
		if len(parts) > 3 {
			if parts[3] == "namespaces" {
				if len(parts) > 5 {
					kr.namespace = parts[4]
					kr.resource = parts[5]
					if len(parts) > 6 {
						kr.resourceName = parts[6]
					}
				} else if len(parts) > 4 {
					kr.resource = parts[3]
					kr.resourceName = parts[4]
					kr.namespace = parts[4]
				} else {
					kr.resource = parts[3]
				}
			} else {
				kr.namespace = ""
				kr.resource = parts[3]
				if len(parts) > 4 {
					kr.resourceName = parts[4]
				}
			}
		}
	}

	// handle verb
	switch r.Method {
	case http.MethodGet:
		if strings.Contains(r.URL.Query().Get("watch"), "true") {
			kr.verb = "watch"
		} else {
			kr.verb = "get"

			if kr.namespace == "" || (kr.resource != "" && kr.resourceName == "") {
				kr.verb = "list"
			}

			if kr.namespace == kr.resourceName {
				kr.namespace = ""
			}
		}
	case http.MethodPost:
		kr.verb = "create"
	case http.MethodPut:
		kr.verb = "update"
	case http.MethodDelete:
		kr.verb = "delete"
		if kr.resource != "" && kr.resourceName == "" {
			kr.verb = "deletecollection"
		}
	case http.MethodPatch:
		kr.verb = "patch"
	default:
		return nil, fmt.Errorf("unsupported HTTP method: %v", r.Method)
	}

	// handle special case overrides
	if kr.resource == "pods" && strings.HasSuffix(strings.Split(r.URL.Path, "?")[0], "/exec") {
		kr.resource = "pods/exec"
	}

	if kr.resource == "pods" && strings.HasSuffix(strings.Split(r.URL.Path, "?")[0], "/portforward") {
		kr.resource = "pods/portforward"
	}

	// handle the -A/--all-namespaces flag where an object is listed in all namespaces
	if kr.verb == "list" && kr.resource != "namespaces" && kr.namespace == "" {
		kr.namespace = "*"
	}

	return kr, nil
}

func evaluateRule(rule sdk.KubernetesRule, kr *kubernetesRequest) bool {
	for k, v := range map[*string][]string{
		&kr.verb:         rule.Verbs,
		&kr.apigroup:     rule.APIGroups,
		&kr.namespace:    rule.Namespaces,
		&kr.resource:     rule.Resources,
		&kr.resourceName: rule.ResourceNames,
	} {
		if *k != "" {
			if *k == "*" {
				if !slice.Contains(v, "*") {
					return false
				}
			} else {
				if !matchesAny(v, *k) {
					return false
				}
			}
		}
	}
	return true
}

func matchesAny(templates []string, check string) bool {
	for _, t := range templates {
		if wildcard.Match(t, check) {
			return true
		}
	}
	return false
}
