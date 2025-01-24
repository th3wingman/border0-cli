package connectorv2

import (
	"fmt"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	pb "github.com/borderzero/border0-proto/connector"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (c *ConnectorService) UpdateSession(update models.SessionUpdate) error {
	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_SessionUpdate{
			SessionUpdate: &pb.SessionUpdateRequest{
				SessionKey:     update.SessionKey,
				SocketId:       update.Socket.SocketID,
				UserData:       update.UserData,
				Result:         string(update.Result),
				AuthInfoFailed: update.AuthInfoFailed,
			},
		},
	}); err != nil {
		c.logger.Error("failed to send session update: %s", zap.Error(err))
	}
	return nil
}

func (c *ConnectorService) UploadRecording(content []byte, socketID, sessionKey, recordingID, recordingType string) error {
	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_UploadRecording{
			UploadRecording: &pb.UploadRecording{
				SessionKey:    sessionKey,
				RecordingId:   recordingID,
				Recording:     content,
				RecordingType: recordingType,
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to send upload recording: %s", err)
	}

	return nil
}

func (c *ConnectorService) CreateSessionEvent(sessionEvent models.SessionEvent) error {
	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_SessionEvent{
			SessionEvent: &pb.SessionEvent{
				SessionKey: sessionEvent.SessionKey,
				SocketId:   sessionEvent.Socket.SocketID,
				Type:       sessionEvent.Type,
				Status:     sessionEvent.Status,
				Metadata:   sessionEvent.Metadata,
			},
		},
	}); err != nil {
		c.logger.Error("failed to send new session event: %s", zap.Error(err))
	}
	return nil
}

func (c *ConnectorService) CreateSession(session models.Session) (*models.SessionCreateResult, error) {
	recChan := make(chan *pb.ControlStreamResponse)
	defer close(recChan)

	requestId := uuid.New().String()
	c.requests.Store(requestId, recChan)
	defer c.requests.Delete(requestId)

	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_Session{Session: &pb.SessionRequest{
			RequestId:  requestId,
			StartTime:  timestamppb.Now(),
			LastSeen:   timestamppb.Now(),
			Email:      session.Email,
			LogType:    session.LogType,
			SocketId:   session.SocketID,
			ServerName: session.ServerName,
			ServerPort: session.ServerPort,
			ClientIp:   session.ClientIP,
			ClientPort: session.ClientPort,
			SessionKey: session.SessionKey,
			Result:     session.Result,
			AuthInfo:   session.AuthInfo,
			Metadata:   session.Metadata,
			EntityUuid: session.EntityUUID,
		}},
	}); err != nil {
		return nil, fmt.Errorf("failed to create new session: %w", err)
	}

	// handle response or timeout
	select {
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timeout waiting for create session response")
	case r := <-recChan:
		response := r.GetSession()
		if response == nil {
			return nil, fmt.Errorf("invalid response")
		}
		if response.GetRequestId() == "" {
			return nil, fmt.Errorf("invalid response")
		}
		return &models.SessionCreateResult{
			SessionKey: response.GetSessionId(),
			SshTicket:  response.GetSshTicket(),
		}, nil
	}
}

func (c *ConnectorService) EndSession(session models.Session) error {
	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_Session{Session: &pb.SessionRequest{
			EndTime:    timestamppb.Now(),
			SocketId:   session.SocketID,
			SessionKey: session.SessionKey,
		}},
	}); err != nil {
		return fmt.Errorf("failed to end session: %w", err)
	}

	return nil
}
