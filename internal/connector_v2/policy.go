package connectorv2

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/borderzero/border0-cli/internal/api/models"
	sdk "github.com/borderzero/border0-go/client"
	"github.com/borderzero/border0-go/types/service"
	pb "github.com/borderzero/border0-proto/connector"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

func (s *ConnectorService) EvaluatePeer(ctx context.Context, socket *models.Socket, clientIP, publicKey string) (email, entityUUID string, allowedActions []any, info map[string][]string, err error) {
	if socket == nil {
		err = fmt.Errorf("socket is nil")
		return
	}

	if clientIP == "" || publicKey == "" {
		err = fmt.Errorf("metadata is invalid")
		return
	}

	email, entityUUID, actions, info, err := s.AuthorizePeerRequest(ctx, socket, clientIP, publicKey)
	if err != nil {
		err = fmt.Errorf("authorization request failed: %w", err)
		return
	}

	for app, actions := range actions {
		if strings.EqualFold(socket.SocketType, app) || app == "*" {
			for _, action := range actions {
				switch action := action.(type) {
				case string:
					allowedActions = append(allowedActions, strings.ToLower(action))
				case *structpb.Struct:
					var permissions models.Permissions

					switch app {
					case service.ServiceTypeSsh:
						var p models.SSHPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.SSH = &p
					case service.ServiceTypeDatabase:
						var p models.DatabasePermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.Database = &p
					case service.ServiceTypeTls:
						var p sdk.TLSPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.TLS = &p
					case service.ServiceTypeRdp:
						var p sdk.RDPPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.RDP = &p
					case service.ServiceTypeVnc:
						var p sdk.VNCPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.VNC = &p
					case service.ServiceTypeVpn:
						var p sdk.VPNPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.VPN = &p
					case service.ServiceTypeHttp:
						var p sdk.HTTPPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.HTTP = &p
					case service.ServiceTypeKubernetes:
						var p sdk.KubernetesPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.Kubernetes = &p
					}
					allowedActions = append(allowedActions, permissions)
				default:
					s.logger.Warn("unknown action type", zap.String("type", fmt.Sprintf("%T", action)))
				}
			}
		}
	}

	return
}

func (s *ConnectorService) Evaluate(ctx context.Context, socket *models.Socket, clientIP, userEmail, sessionKey string) (allowedActions []any, info map[string][]string, err error) {
	if socket == nil {
		err = fmt.Errorf("socket is nil")
		return
	}

	if clientIP == "" || userEmail == "" || sessionKey == "" {
		err = fmt.Errorf("metadata is invalid")
		return
	}

	actions, info, err := s.AuthorizeRequest(ctx, socket, clientIP, userEmail, sessionKey)
	if err != nil {
		err = fmt.Errorf("authorization request failed: %w", err)
		return
	}

	for app, actions := range actions {
		if strings.EqualFold(socket.SocketType, app) || app == "*" {
			for _, action := range actions {
				switch action := action.(type) {
				case string:
					allowedActions = append(allowedActions, strings.ToLower(action))
				case *structpb.Struct:
					var permissions models.Permissions

					switch app {
					case service.ServiceTypeSsh:
						var p models.SSHPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.SSH = &p
					case service.ServiceTypeDatabase:
						var p models.DatabasePermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.Database = &p
					case service.ServiceTypeTls:
						var p sdk.TLSPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.TLS = &p
					case service.ServiceTypeRdp:
						var p sdk.RDPPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.RDP = &p
					case service.ServiceTypeVnc:
						var p sdk.VNCPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.VNC = &p
					case service.ServiceTypeVpn:
						var p sdk.VPNPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.VPN = &p
					case service.ServiceTypeHttp:
						var p sdk.HTTPPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.HTTP = &p
					case service.ServiceTypeKubernetes:
						var p sdk.KubernetesPermissions
						if err := parsePermissions(action, &p, s.logger); err != nil {
							continue
						}
						permissions.Kubernetes = &p
					}
					allowedActions = append(allowedActions, permissions)
				default:
					s.logger.Warn("unknown action type", zap.String("type", fmt.Sprintf("%T", action)))
				}
			}
		}
	}

	return
}

func parsePermissions(action *structpb.Struct, permissions any, logger *zap.Logger) error {
	jsonBytes, err := action.MarshalJSON()
	if err != nil {
		logger.Error("failed to parse policy struct", zap.Error(err))
		return err
	}

	err = json.Unmarshal(jsonBytes, permissions)
	if err != nil {
		logger.Error("failed to parse policy json", zap.Error(err))
		return err
	}

	return nil
}

func (c *ConnectorService) AuthorizeRequest(ctx context.Context, socket *models.Socket, clientIP, userEmail, sessionKey string) (map[string][]any, map[string][]string, error) {
	requestId := uuid.New().String()

	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_Authorize{
			Authorize: &pb.AuthorizeRequest{
				RequestId:  requestId,
				SocketId:   socket.SocketID,
				Protocol:   socket.SocketType,
				IpAddress:  clientIP,
				UserEmail:  userEmail,
				SessionKey: sessionKey,
			},
		},
	}); err != nil {
		return nil, nil, fmt.Errorf("failed to send authorize request: %w", err)
	}

	recChan := make(chan *pb.ControlStreamResponse)
	c.requests.Store(requestId, recChan)
	defer c.requests.Delete(requestId)
	defer close(recChan)

	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case r := <-recChan:
		response := r.GetAuthorize()
		if response == nil {
			return nil, nil, fmt.Errorf("invalid response")
		}

		allowedActions := make(map[string][]any)
		for app, actions := range response.GetAllowedActions() {
			for _, action := range actions.GetValues() {
				allowedActions[app] = append(allowedActions[app], strings.ToLower(action))
			}
		}

		for app, actions := range response.GetPermissions() {
			for _, action := range actions.GetPermissions() {
				allowedActions[app] = append(allowedActions[app], action)
			}
		}

		info := make(map[string][]string)
		for i, v := range response.GetInfo() {
			info[i] = v.GetValues()
		}

		return allowedActions, info, nil
	}
}

func (c *ConnectorService) AuthorizePeerRequest(ctx context.Context, socket *models.Socket, clientIP, publicKey string) (string, string, map[string][]any, map[string][]string, error) {
	requestId := uuid.New().String()

	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_AuthorizePeer{
			AuthorizePeer: &pb.AuthorizePeerRequest{
				RequestId: requestId,
				SocketId:  socket.SocketID,
				Protocol:  socket.SocketType,
				IpAddress: clientIP,
				PublicKey: publicKey,
			},
		},
	}); err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to send authorize request: %w", err)
	}

	recChan := make(chan *pb.ControlStreamResponse)
	c.requests.Store(requestId, recChan)
	defer c.requests.Delete(requestId)
	defer close(recChan)

	select {
	case <-ctx.Done():
		return "", "", nil, nil, ctx.Err()
	case r := <-recChan:
		response := r.GetAuthorize()
		if response == nil {
			return "", "", nil, nil, fmt.Errorf("invalid response")
		}

		email := response.GetEmail()
		if email == "" {
			return "", "", nil, nil, fmt.Errorf("email is empty")
		}

		allowedActions := make(map[string][]any)
		for app, actions := range response.GetAllowedActions() {
			for _, action := range actions.GetValues() {
				allowedActions[app] = append(allowedActions[app], strings.ToLower(action))
			}
		}

		for app, actions := range response.GetPermissions() {
			for _, action := range actions.GetPermissions() {
				allowedActions[app] = append(allowedActions[app], action)
			}
		}

		info := make(map[string][]string)
		for i, v := range response.GetInfo() {
			info[i] = v.GetValues()
		}

		return email, response.GetEntityUuid(), allowedActions, info, nil
	}
}
