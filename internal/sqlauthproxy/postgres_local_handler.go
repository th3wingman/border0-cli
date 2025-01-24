package sqlauthproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/util/recorder"
	"github.com/borderzero/border0-go/lib/types/pointer"
	"github.com/borderzero/border0-go/types/recordings"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"vitess.io/vitess/go/vt/sqlparser"
)

type postgresLocalHandler struct {
	logger          *zap.Logger
	metadata        *border0.ConnMetadata
	border0API      border0.Border0API
	socket          models.Socket
	lastAuth        time.Time
	recordingChan   chan message
	clientConn      *pgconn.HijackedConn
	serverConn      net.Conn
	serverBackend   *pgproto3.Backend
	clientFrontend  *pgproto3.Frontend
	preparedQueries map[string]string
	binds           map[string]bind
	database        string
	queryStats      QueryStats
}

type QueryStats struct {
	query        string
	startTime    time.Time
	rowsReturned *int64
	rowsAffected *int64
	errorMessage *string
}

type bind struct {
	query  string
	params [][]byte
}

func (h *postgresLocalHandler) HandleConnection(clientConn *pgconn.HijackedConn) {
	h.clientConn = clientConn
	h.clientFrontend = pgproto3.NewFrontend(pgproto3.NewChunkReader(h.clientConn.Conn), h.clientConn.Conn)

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	if h.metadata != nil {
		var max_session_duration int

		for _, action := range h.metadata.AllowedActions {
			switch action := action.(type) {
			case string:
			case models.Permissions:
				if action.Database != nil {
					if action.Database.MaxSessionDurationSeconds != nil && *action.Database.MaxSessionDurationSeconds > max_session_duration {
						max_session_duration = *action.Database.MaxSessionDurationSeconds
					}
				}
			}
		}

		if max_session_duration > 0 {
			go func() {
				select {
				case <-time.After(time.Duration(max_session_duration) * time.Second):
					metadata, err := json.Marshal(struct {
						SessionDuration int    `json:"session_duration"`
						UpstreamType    string `json:"upstream_type"`
					}{max_session_duration, h.socket.UpstreamType})

					if err != nil {
						h.logger.Error("failed to create session event", zap.Error(err))
					} else {
						if err := h.border0API.CreateSessionEvent(models.SessionEvent{
							SessionKey: h.metadata.SessionKey,
							Socket:     &h.socket,
							Type:       "database_session_duration",
							Status:     "denied",
							Metadata:   string(metadata),
						}); err != nil {
							h.logger.Error("failed to create session event", zap.Error(err))
						}

						cancel()
					}

				case <-ctx.Done():
				}
			}()
		}
	}

	if h.socket.RecordingEnabled {
		r, err := recorder.NewJSONLRecorder[message](h.logger, h.border0API, h.socket.SocketID, h.metadata.SessionKey, recordings.RecordingTypeDatabaseQueryLog)
		if err != nil {
			if err := h.ErrorEvent("database_recording", fmt.Sprintf("failed to record session: %s", err)); err != nil {
				h.logger.Error("failed to create session event", zap.Error(err))
			}
			return
		}
		r.Record(h.recordingChan)
		defer close(h.recordingChan)
	}

	go func() {
		for {
			msg, err := h.clientFrontend.Receive()
			if err != nil {
				return
			}

			select {
			case <-ctx.Done():
				return
			default:
			}

			if err := h.handleServerMessage(msg); err != nil {
				return
			}
		}
	}()

	for {
		msg, err := h.serverBackend.Receive()
		if err != nil {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := h.handleClientMessage(msg); err != nil {
			if err := h.ErrorEvent("database_query", err.Error()); err != nil {
				h.logger.Error("failed to create session event", zap.Error(err))
			}

			return
		}
	}
}

func (h *postgresLocalHandler) handleServerMessage(msg pgproto3.BackendMessage) error {
	switch m := msg.(type) {
	case *pgproto3.CommandComplete:
		if h.queryStats.query != "" {
			commandTag := pgconn.CommandTag(m.CommandTag)
			rows := commandTag.RowsAffected()
			if commandTag.Select() {
				h.queryStats.rowsReturned = &rows
			} else if commandTag.Insert() || commandTag.Update() || commandTag.Delete() {
				h.queryStats.rowsAffected = &rows
			}
			h.record(h.queryStats.query, nil, nil, time.Since(h.queryStats.startTime).Milliseconds(), h.queryStats.rowsReturned, h.queryStats.rowsAffected)
		}
	case *pgproto3.ErrorResponse:
		h.queryStats.errorMessage = &m.Message
		h.record(h.queryStats.query, nil, h.queryStats.errorMessage, time.Since(h.queryStats.startTime).Milliseconds(), nil, nil)
	}
	return h.serverBackend.Send(msg)
}

func (h *postgresLocalHandler) handleClientMessage(msg pgproto3.FrontendMessage) error {
	switch m := msg.(type) {
	case *pgproto3.Terminate:
		h.clientFrontend.Send(msg)
		return nil
	case *pgproto3.Query:
		allowed, stmtType, err := h.isAllowed(m.String)
		if err != nil {
			return fmt.Errorf("failed to authorize: %w", err)
		}

		if !allowed {
			result := "command denied by policy"
			h.record(m.String, nil, &result, 0, nil, nil)
			if err := h.serverBackend.Send(&pgproto3.ErrorResponse{
				Severity: "ERROR",
				Code:     "28000",
				Message:  "User not authorized",
				Detail:   fmt.Sprintf("User \"%s\" is not allowed to execute this command.", h.metadata.UserEmail),
			}); err != nil {
				return err
			}

			metadata, err := json.Marshal(struct {
				QueryType string `json:"query_type"`
				Database  string `json:"database"`
			}{stmtType, h.database})
			if err != nil {
				h.logger.Error("failed to create session event", zap.Error(err))
			} else {
				if err := h.border0API.CreateSessionEvent(models.SessionEvent{
					SessionKey: h.metadata.SessionKey,
					Socket:     &h.socket,
					Type:       "database_query",
					Status:     "denied",
					Metadata:   string(metadata),
				}); err != nil {
					h.logger.Error("failed to create session event", zap.Error(err))
				}
			}

			return h.serverBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		}

		h.queryStats = QueryStats{
			query:        m.String,
			startTime:    time.Now(),
			rowsReturned: nil,
			rowsAffected: nil,
			errorMessage: nil,
		}

		return h.clientFrontend.Send(m)
	case *pgproto3.Parse:
		h.preparedQueries[m.Name] = m.Query
		return h.clientFrontend.Send(msg)
	case *pgproto3.Bind:
		if _, ok := h.preparedQueries[m.PreparedStatement]; !ok {
			if err := h.serverBackend.Send(&pgproto3.ErrorResponse{
				Severity: "ERROR",
				Code:     "26000",
				Message:  "undefined prepared statement",
				Detail:   fmt.Sprintf("There is no prepared statement with name \"%s\" available.", m.PreparedStatement),
			}); err != nil {
				return err
			}

			return h.serverBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		}

		h.binds[m.DestinationPortal] = bind{
			query:  h.preparedQueries[m.PreparedStatement],
			params: m.Parameters,
		}

		return h.clientFrontend.Send(m)
	case *pgproto3.Describe, *pgproto3.Sync:
		return h.clientFrontend.Send(msg)
	case *pgproto3.Execute:
		var bind bind
		var ok bool

		if bind, ok = h.binds[m.Portal]; !ok {
			if err := h.serverBackend.Send(&pgproto3.ErrorResponse{
				Severity: "ERROR",
				Code:     "26000",
				Message:  "undefined prepared statement",
				Detail:   fmt.Sprintf("There is no prepared statement with name \"%s\" available.", m.Portal),
			}); err != nil {
				return err
			}

			return h.serverBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		}

		allowed, stmtType, err := h.isAllowed(bind.query)
		if err != nil {
			return fmt.Errorf("failed to authorize: %w", err)
		}

		if !allowed {
			result := "command denied by policy"
			h.record(bind.query, nil, &result, 0, nil, nil)
			if err := h.serverBackend.Send(&pgproto3.ErrorResponse{
				Severity: "ERROR",
				Code:     "28000",
				Message:  "User not authorized",
				Detail:   fmt.Sprintf("User \"%s\" is not allowed to execute this command.", h.metadata.UserEmail),
			}); err != nil {
				return err
			}

			metadata, err := json.Marshal(struct {
				QueryType string `json:"query_type"`
				Database  string `json:"database"`
			}{stmtType, h.database})
			if err != nil {
				h.logger.Error("failed to create session event", zap.Error(err))
			} else {
				if err := h.border0API.CreateSessionEvent(models.SessionEvent{
					SessionKey: h.metadata.SessionKey,
					Socket:     &h.socket,
					Type:       "database_query",
					Status:     "denied",
					Metadata:   string(metadata),
				}); err != nil {
					h.logger.Error("failed to create session event", zap.Error(err))
				}
			}

			return h.serverBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		}

		h.queryStats = QueryStats{
			query:        fmt.Sprintf("%s with args %v", bind.query, bind.params),
			startTime:    time.Now(),
			rowsReturned: nil,
			rowsAffected: nil,
			errorMessage: nil,
		}

		return h.clientFrontend.Send(m)
	default:
		return h.serverBackend.Send(&pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "26000",
			Message:  "unsupported message type",
			Detail:   fmt.Sprintf("Message type %T is not supported", msg),
		})
	}
}

func (h *postgresLocalHandler) isAllowed(query string) (bool, string, error) {
	if time.Since(h.lastAuth) > authTTL {
		var clientIP string
		if conn, ok := h.serverConn.(*border0.PrivateNetworkConn); ok {
			if ip, err := conn.GetPeerIP(); err != nil {
				return false, "", fmt.Errorf("failed to get peer IP: %w", err)
			} else {
				clientIP = ip
			}
		} else {
			if ip, _, err := net.SplitHostPort(h.metadata.ClientIP); err != nil {
				return false, "", fmt.Errorf("failed to parse client ip: %w", err)
			} else {
				clientIP = ip
			}
		}

		actions, _, err := h.border0API.Evaluate(context.TODO(), &h.socket, clientIP, h.metadata.UserEmail, h.metadata.SessionKey)
		if err != nil {
			return false, "", err
		}

		h.metadata.AllowedActions = actions
		h.lastAuth = time.Now()
	}

	stmtType := sqlparser.Preview(query)

	for _, aa := range h.metadata.AllowedActions {
		switch aa := aa.(type) {
		case string:
			if strings.EqualFold(aa, stmtType.String()) || aa == "*" {
				return true, stmtType.String(), nil
			}
		case models.Permissions:
			if aa.Database != nil {
				if aa.Database.AllowedDatabases == nil {
					return true, stmtType.String(), nil
				}

				database := h.database
				switch stmtType.String() {
				case "DDL", "UNKNOWN":
					p, err := sqlparser.New(sqlparser.Options{})
					if err != nil {
						return false, stmtType.String(), errors.Wrap(err, "failed to create parser")
					}

					stmt, err := p.Parse(query)
					if err != nil {
						return false, stmtType.String(), errors.Wrap(err, "failed to parse query")
					}

					switch stmt := stmt.(type) {
					case *sqlparser.CreateDatabase:
						database = stmt.GetDatabaseName()
					case *sqlparser.DropDatabase:
						database = stmt.GetDatabaseName()
					case *sqlparser.AlterDatabase:
						database = stmt.GetDatabaseName()
					case *sqlparser.PrepareStmt:
						stmtType = sqlparser.StmtPrepare
					case *sqlparser.ExecuteStmt:
						stmtType = sqlparser.StmtExecute
					case *sqlparser.DeallocateStmt:
						stmtType = sqlparser.StmtDeallocate
					}
				}

				for _, db := range *aa.Database.AllowedDatabases {
					if db.Database == database || db.Database == "*" {
						if db.AllowedQueryTypes == nil {
							return true, stmtType.String(), nil
						}

						for _, qt := range *db.AllowedQueryTypes {
							switch qt {
							case "ReadWrite":
								switch stmtType.String() {
								case "SELECT", "INSERT", "UPDATE", "REPLACE", "DELETE", "DDL", "BEGIN", "ROLLBACK", "COMMIT", "REVERT", "LOCK_TABLES", "UNLOCK_TABLES", "SHOW", "SET", "EXPLAIN", "ANALYZE", "RELEASE", "PREPARE", "EXECUTE", "DEALLOCATE PREPARE":
									return true, stmtType.String(), nil
								}
							case "ReadOnly":
								switch stmtType.String() {
								case "SELECT", "SHOW", "SET", "EXPLAIN", "PREPARE", "EXECUTE", "DEALLOCATE PREPARE":
									return true, stmtType.String(), nil
								}
							default:
								if strings.EqualFold(qt, stmtType.String()) {
									return true, stmtType.String(), nil
								}
							}
						}
					}
				}
			}
		default:
			return false, stmtType.String(), fmt.Errorf("unknown action type: %T", aa)
		}
	}

	return false, stmtType.String(), nil
}

func (h *postgresLocalHandler) record(command string, status *uint16, result *string, duration int64, rows *int64, affectedRows *int64) {
	if !h.socket.RecordingEnabled {
		return
	}

	var affectedRowsUint64 *uint64
	if affectedRows != nil {
		affectedRowsUint64 = pointer.To(uint64(*affectedRows))

	}

	h.recordingChan <- message{
		Time:         time.Now().UnixMilli(),
		Database:     h.database,
		Command:      command,
		Status:       status,
		Result:       result,
		Duration:     duration,
		Rows:         rows,
		AffectedRows: affectedRowsUint64,
	}
}

func (h *postgresLocalHandler) ClientConn(clientConn *pgconn.HijackedConn) {
	h.clientConn = clientConn
}

func (h *postgresLocalHandler) ErrorEvent(eventType string, message string) error {
	metadata, err := json.Marshal(struct {
		Error string `json:"error"`
	}{message})
	if err != nil {
		return err
	}

	return h.border0API.CreateSessionEvent(models.SessionEvent{
		SessionKey: h.metadata.SessionKey,
		Socket:     &h.socket,
		Type:       eventType,
		Status:     "error",
		Metadata:   string(metadata),
	})
}
