package sqlauthproxy

import (
	"context"
	"encoding/hex"
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
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	pe "github.com/pingcap/errors"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"vitess.io/vitess/go/vt/sqlparser"
)

type mysqlLocalHandler struct {
	logger          *zap.Logger
	metadata        *border0.ConnMetadata
	border0API      border0.Border0API
	socket          models.Socket
	database        string
	clientConn      *client.Conn
	serverConn      *server.Conn
	statements      map[int64]*client.Stmt
	preparedQueries map[int64]string
	lastAuth        time.Time
	recordingChan   chan message
	variables       map[string]string
}

type queryValidator struct {
	query                string
	permissions          *models.DatabasePermissions
	database             string
	stmtType             string
	allowedDatabaseFound bool
	handler              *mysqlLocalHandler
}

var _ server.Handler = &mysqlLocalHandler{}

func (h *mysqlLocalHandler) Database() string {
	return h.database
}

func (h *mysqlLocalHandler) ClientConn(clientConn *client.Conn) {
	h.clientConn = clientConn
}

func (h *mysqlLocalHandler) HandleConnection(serverConn *server.Conn) {
	h.serverConn = serverConn

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	if h.metadata != nil {
		var allowed bool
		var max_session_duration int

		for _, action := range h.metadata.AllowedActions {
			switch action := action.(type) {
			case string:
				allowed = true
			case models.Permissions:
				if action.Database != nil {
					allowed = true
					if action.Database.MaxSessionDurationSeconds != nil && *action.Database.MaxSessionDurationSeconds > max_session_duration {
						max_session_duration = *action.Database.MaxSessionDurationSeconds
					}
				}
			}
		}

		if !allowed {
			if err := h.border0API.UpdateSession(models.SessionUpdate{
				SessionKey:     h.metadata.SessionKey,
				Socket:         &h.socket,
				Result:         models.ResultDenied,
				AuthInfoFailed: "database access denied by policy",
			}); err != nil {
				h.logger.Error("failed to update session", zap.Error(err))
			}

			return
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

	errChan := make(chan error)
	go func() {
		for {
			errChan <- serverConn.HandleCommand()
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()

	for {
		select {
		case err := <-errChan:
			if err != nil {
				if errors.As(err, &mysql.ErrBadConn) {
					return
				}

				if err := h.ErrorEvent("database_connection", fmt.Sprintf("connection closed: %s", err)); err != nil {
					h.logger.Error("failed to create session event", zap.Error(err))
				}
				return
			}
		case <-ctx.Done():
			return
		}

	}
}

func (h *mysqlLocalHandler) UseDB(dbName string) error {
	start := time.Now()
	var err error

	query := fmt.Sprintf("USE %s", dbName)
	defer func() {
		var pErr *string
		if err != nil {
			pErr = pointer.To(err.Error())
		}

		h.record(query, nil, pErr, time.Since(start).Milliseconds(), nil, nil)
	}()

	allowed, stmtType, err := h.isAllowed(query)
	if err != nil {
		err = errors.New("failed to parse query")
		return mysql.NewError(
			mysql.ER_PARSE_ERROR,
			fmt.Sprintf("failed to parse query: %s", query),
		)
	}

	if !allowed {
		err = errors.New("database access denied by policy")

		metadata, err := json.Marshal(struct {
			QueryType string `json:"query_type"`
			Database  string `json:"database"`
		}{stmtType, dbName})
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

		return mysql.NewError(
			mysql.ER_DBACCESS_DENIED_ERROR,
			fmt.Sprintf("access denied for database %s", dbName),
		)
	}

	err = h.clientConn.UseDB(dbName)
	if err != nil {
		return pe.Unwrap(err)
	}

	h.database = dbName

	return nil
}

func (h *mysqlLocalHandler) HandleFieldList(table string, fieldWildcard string) ([]*mysql.Field, error) {
	fields, err := h.clientConn.FieldList(table, fieldWildcard)
	if err != nil {
		return nil, errors.Wrap(err, "failed to HandleFieldList")
	}

	return fields, nil
}

func (h *mysqlLocalHandler) HandleOtherCommand(cmd byte, data []byte) error {
	return mysql.NewError(
		mysql.ER_UNKNOWN_ERROR,
		fmt.Sprintf("command %d is not supported", cmd),
	)
}

func (h *mysqlLocalHandler) handleMultiStatementQuery(stmts []sqlparser.Statement, query string) (*mysql.Result, error) {
	for _, stmt := range stmts {
		// check action allowed
		allowed, stmtType, err := h.isAllowed(sqlparser.String(stmt))
		if err != nil {
			return nil, mysql.NewError(
				mysql.ER_PARSE_ERROR,
				err.Error(),
			)
		}

		if !allowed {
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

			return nil, mysql.NewError(
				mysql.ER_ACCESS_DENIED_ERROR,
				fmt.Sprintf("query %s is not allowed", query),
			)
		}
	}

	count := 0
	start := time.Now()

	return h.clientConn.ExecuteMultiple(query, func(r *mysql.Result, err error) {
		var affectedRows *uint64
		var rows *int64
		var status *uint16

		defer func() {
			var pErr *string
			if err != nil {
				pErr = pointer.To(err.Error())
			}

			h.record(sqlparser.String(stmts[count]), status, pErr, time.Since(start).Milliseconds(), rows, affectedRows)
			count++
			start = time.Now()
		}()

		if err != nil {
			h.serverConn.UnsetStatus(mysql.SERVER_MORE_RESULTS_EXISTS)
			h.serverConn.WriteValue(err)
		} else {
			// set proper status according to server results
			h.serverConn.SetStatus(mysql.SERVER_MORE_RESULTS_EXISTS)
			// if this is the last result, unset the more_results status
			if r.Status&mysql.SERVER_MORE_RESULTS_EXISTS == 0 {
				h.serverConn.UnsetStatus(mysql.SERVER_MORE_RESULTS_EXISTS)
			}

			status = pointer.To(r.Status)
			rows = pointer.To(int64(r.RowNumber()))
			affectedRows = &r.AffectedRows

			switch s := stmts[count].(type) {
			case *sqlparser.Use:
				if r != nil {
					h.database = s.DBName.String()
				}
				h.serverConn.WriteValue(r)
			case *sqlparser.Show:
				switch stmt := s.Internal.(type) {
				case *sqlparser.ShowBasic:
					if stmt.Command == 11 { // show databases
						databases, err := h.handleShowDatabases(r)
						if err != nil {
							h.serverConn.WriteValue(err)
						} else {
							h.serverConn.WriteValue(databases)
						}
						status = pointer.To(databases.Status)
						rows = pointer.To(int64(databases.RowNumber()))
						affectedRows = &databases.AffectedRows
					}
				}
			default:
				h.serverConn.WriteValue(r)
			}
		}
	})
}

func (h *mysqlLocalHandler) HandleQuery(query string) (*mysql.Result, error) {
	start := time.Now()
	var err error
	var affectedRows *uint64
	var rows *int64
	var status *uint16
	var res *mysql.Result
	var doNotRecord bool

	defer func() {
		var pErr *string
		if err != nil {
			pErr = pointer.To(err.Error())
		}

		if !doNotRecord {
			h.record(query, status, pErr, time.Since(start).Milliseconds(), rows, affectedRows)
		}
	}()

	p, err := sqlparser.New(sqlparser.Options{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create parser")
	}

	if h.serverConn.Capability()&mysql.CLIENT_MULTI_STATEMENTS > 0 {
		stmts, sErr := p.SplitStatements(query)
		if sErr != nil {
			err = sErr
			if err := h.ErrorEvent("database_policy_check", fmt.Sprintf("failed to parse query: %s", err)); err != nil {
				h.logger.Error("failed to create session event", zap.Error(err))
			}

			return nil, mysql.NewError(
				mysql.ER_PARSE_ERROR,
				err.Error(),
			)
		}

		if len(stmts) > 1 {
			res, err = h.handleMultiStatementQuery(stmts, query)
			if err == nil {
				doNotRecord = true
			}

			return res, err
		}
	}

	// check action allowed
	allowed, stmtType, err := h.isAllowed(query)
	if err != nil {
		return nil, mysql.NewError(
			mysql.ER_PARSE_ERROR,
			err.Error(),
		)
	}

	if !allowed {
		err = errors.New("query denied by policy")

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

		return nil, mysql.NewError(
			mysql.ER_ACCESS_DENIED_ERROR,
			fmt.Sprintf("query %s is not allowed", query),
		)
	}

	stmt, _ := p.Parse(query)
	start = time.Now()
	switch s := stmt.(type) {
	case *sqlparser.Select:
		var streamRows int64
		res = &mysql.Result{}
		err = h.clientConn.ExecuteSelectStreaming(query, res,
			// called per row within result
			func(row []mysql.FieldValue) error {
				streamRows++
				return h.serverConn.WriteValue(row)
			},
			// called per result
			func(r *mysql.Result) error {
				return h.serverConn.WriteValue(r)
			},
		)

		status = pointer.To(res.Status)
		rows = pointer.To(streamRows)
		affectedRows = &res.AffectedRows

		return res, err
	case *sqlparser.Use:
		res, err = h.clientConn.Execute(query)
		if res != nil {
			affectedRows = &res.AffectedRows
			r := int64(res.RowNumber())
			rows = pointer.To(r)
			status = pointer.To(res.Status)

			h.database = s.DBName.String()
		}

		return res, err
	case *sqlparser.Show:
		switch stmt := s.Internal.(type) {
		case *sqlparser.ShowBasic:
			if stmt.Command == 11 { // show databases
				showDatabasesResult, err := h.clientConn.Execute("SHOW DATABASES")
				if err != nil {
					if err := h.ErrorEvent("database_show", fmt.Sprintf("failed to retrieve databases: %s", err)); err != nil {
						h.logger.Error("failed to create session event", zap.Error(err))
					}

					return showDatabasesResult, err
				}

				res, err := h.handleShowDatabases(showDatabasesResult)
				if res != nil {
					affectedRows = &res.AffectedRows
					r := int64(res.RowNumber())
					rows = pointer.To(r)
					status = pointer.To(res.Status)
				}

				return res, err
			}
		}

		res, err = h.clientConn.Execute(query)
		if res != nil {
			affectedRows = &res.AffectedRows
			r := int64(res.RowNumber())
			rows = pointer.To(r)
			status = pointer.To(res.Status)
		}
		return res, err
	default:
		res, err = h.clientConn.Execute(query)
		if res != nil {
			affectedRows = &res.AffectedRows
			r := int64(res.RowNumber())
			rows = pointer.To(r)
			status = pointer.To(res.Status)
		}

		return res, err
	}
}

func (h *mysqlLocalHandler) handleShowDatabases(res *mysql.Result) (*mysql.Result, error) {
	var allowedDatabases []string
	for _, row := range res.Values {
		if len(row) == 0 {
			continue
		}

		database := string(row[0].AsString())
		allowed, _, err := h.isAllowed(fmt.Sprintf("USE %s", database))
		if err != nil {
			return nil, fmt.Errorf("failed to authorize: %w", err)
		}

		if allowed {
			allowedDatabases = append(allowedDatabases, database)
		}
	}

	// Create a result set with the allowed databases
	columnNames := []string{"Database"}
	values := make([][]interface{}, len(allowedDatabases))
	for i, db := range allowedDatabases {
		values[i] = []interface{}{db}
	}

	// Build the result set
	resultset, err := mysql.BuildSimpleTextResultset(columnNames, values)
	if err != nil {
		return nil, err
	}

	return &mysql.Result{
		Status:       res.Status,
		InsertId:     res.InsertId,
		AffectedRows: uint64(len(allowedDatabases)),
		Resultset:    resultset,
	}, nil
}

func (h *mysqlLocalHandler) HandleStmtClose(context interface{}) error {
	intContext, ok := context.(int64)
	if !ok {
		return nil
	}

	stmt, ok := h.statements[intContext]
	if !ok {
		return nil
	}

	if err := stmt.Close(); err != nil {
		return errors.Wrap(err, "failed to HandleStmtClose")
	}

	if _, ok = h.preparedQueries[intContext]; ok {
		delete(h.preparedQueries, intContext)
	}

	return nil
}

func (h *mysqlLocalHandler) HandleStmtExecute(context interface{}, query string, args []interface{}) (*mysql.Result, error) {
	start := time.Now()
	var err error
	queryStr := fmt.Sprintf("%s with args %v", query, args)
	var affectedRows *uint64
	var status *uint16
	var rows *int64

	defer func() {
		var pErr *string
		if err != nil {
			pErr = pointer.To(err.Error())
		}

		h.record(queryStr, status, pErr, time.Since(start).Milliseconds(), rows, affectedRows)
	}()

	intContext, ok := context.(int64)
	if !ok {
		return nil, fmt.Errorf("invalid context")
	}

	// check action allowed
	allowed, stmtType, err := h.isAllowed(query)
	if err != nil {
		return nil, fmt.Errorf("failed to authorize: %w", err)
	}

	if !allowed {
		metadata, jerr := json.Marshal(struct {
			QueryType string `json:"query_type"`
			Database  string `json:"database"`
		}{stmtType, h.database})
		if jerr != nil {
			h.logger.Error("failed to create session event", zap.Error(jerr))
		} else {
			if err := h.border0API.CreateSessionEvent(models.SessionEvent{
				SessionKey: h.metadata.SessionKey,
				Socket:     &h.socket,
				Type:       "database_execute",
				Status:     "denied",
				Metadata:   string(metadata),
			}); err != nil {
				h.logger.Error("failed to create session event", zap.Error(err))
			}
		}

		err = errors.New("command denied by policy")
		return nil, mysql.NewError(
			mysql.ER_ACCESS_DENIED_ERROR,
			fmt.Sprintf("command %s is not allowed", query),
		)
	}

	if stmt, ok := h.statements[intContext]; !ok {
		inlineStmt, err := h.clientConn.Prepare(query)

		if err != nil {
			err = errors.Wrap(err, "failed to prepare")
			return nil, err
		}

		res, err := inlineStmt.Execute(args...)
		if res != nil {
			affectedRows = &res.AffectedRows
			r := int64(res.RowNumber())
			rows = pointer.To(r)
			status = pointer.To(res.Status)
		}

		return res, err
	} else {
		var query string
		if query, ok = h.preparedQueries[intContext]; !ok {
			return nil, fmt.Errorf("no such query")
		}

		queryStr = fmt.Sprintf("%s with args %v", query, args)
		res, err := stmt.Execute(args...)
		if res != nil {
			affectedRows = &res.AffectedRows
			r := int64(res.RowNumber())
			rows = pointer.To(r)
			status = pointer.To(res.Status)
		}

		return res, err
	}
}

func (h *mysqlLocalHandler) HandleStmtPrepare(query string) (int, int, interface{}, error) {
	// check action allowed
	allowed, stmtType, err := h.isAllowed(query)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("failed to authorize: %w", err)
	}

	if !allowed {
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
				Type:       "database_prepare",
				Status:     "denied",
				Metadata:   string(metadata),
			}); err != nil {
				h.logger.Error("failed to create session event", zap.Error(err))
			}
		}

		h.record(query, nil, pointer.To("command denied by policy"), 0, nil, nil)
		return 0, 0, nil, mysql.NewError(
			mysql.ER_ACCESS_DENIED_ERROR,
			fmt.Sprintf("command %s is not allowed", query),
		)
	}

	stmt, err := h.clientConn.Prepare(query)

	if err != nil {
		return 0, 0, nil, errors.Wrap(err, "failed to HandleStmtPrepare")
	}

	id := time.Now().UnixNano()
	h.statements[id] = stmt
	h.preparedQueries[id] = query

	paramNum := stmt.ParamNum()
	colNum := stmt.ColumnNum()

	return paramNum, colNum, id, nil
}

func (h *mysqlLocalHandler) isAllowed(query string) (bool, string, error) {
	if time.Since(h.lastAuth) > authTTL {
		var clientIP string
		if conn, ok := h.serverConn.Conn.Conn.(*border0.PrivateNetworkConn); ok {
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
			if err := h.ErrorEvent("database_policy_check", err.Error()); err != nil {
				h.logger.Error("failed to create session event", zap.Error(err))
			}
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

				q := &queryValidator{
					query:       query,
					permissions: aa.Database,
					database:    h.database,
					stmtType:    stmtType.String(),
					handler:     h,
				}

				// unsupported statements in the parser
				switch stmtType.String() {
				case "PRIV":
					if q.isDatabaseAllowed("") {
						return true, stmtType.String(), nil
					}
					continue
				case "DDL":
					if strings.HasPrefix(strings.ToUpper(query), "CREATE USER") ||
						strings.HasPrefix(strings.ToUpper(query), "ALTER USER") ||
						strings.HasPrefix(strings.ToUpper(query), "DROP USER") ||
						strings.HasPrefix(strings.ToUpper(query), "RENAME USER") {
						if q.isDatabaseAllowed("mysql") {
							return true, stmtType.String(), nil
						}
						continue
					}
				}

				p, err := sqlparser.New(sqlparser.Options{})
				if err != nil {
					if err := h.ErrorEvent("database_policy_check", fmt.Sprintf("failed to parse query: %s", err)); err != nil {
						h.logger.Error("failed to create session event", zap.Error(err))
					}

					return false, stmtType.String(), fmt.Errorf("failed to create sqlparser: %w", err)
				}

				stmt, err := p.Parse(query)
				if err != nil {
					if err := h.ErrorEvent("database_policy_check", fmt.Sprintf("failed to parse query: %s", err)); err != nil {
						h.logger.Error("failed to create session event", zap.Error(err))
					}

					return false, stmtType.String(), err
				}

				err = sqlparser.Walk(q.tableVisitor, stmt)
				if err != nil {
					continue
				}

				if !q.allowedDatabaseFound && !q.isDatabaseAllowed(q.database) {
					continue
				}

				return true, stmtType.String(), nil
			}
		}
	}

	return false, stmtType.String(), nil
}

func (q *queryValidator) notAllowed(database string) error {
	if database == "" {
		return fmt.Errorf("database %s is not allowed", q.database)
	} else {
		return fmt.Errorf("database %s is not allowed", database)
	}
}

func (q *queryValidator) tableVisitor(node sqlparser.SQLNode) (kontinue bool, err error) {
	switch node := node.(type) {
	case sqlparser.TableName:
		if !q.isDatabaseAllowed(node.Qualifier.String()) {
			return false, q.notAllowed(node.Qualifier.String())
		}
	case *sqlparser.Use:
		if !q.isDatabaseAllowed(node.DBName.String()) {
			return false, q.notAllowed(node.DBName.String())
		}
	case *sqlparser.CreateDatabase:
		if !q.isDatabaseAllowed(node.GetDatabaseName()) {
			return false, q.notAllowed(node.GetDatabaseName())
		}
	case *sqlparser.DropDatabase:
		if !q.isDatabaseAllowed(node.GetDatabaseName()) {
			return false, q.notAllowed(node.GetDatabaseName())
		}
	case *sqlparser.AlterDatabase:
		if !q.isDatabaseAllowed(node.GetDatabaseName()) {
			return false, q.notAllowed(node.GetDatabaseName())
		}
	case *sqlparser.ShowCreate:
		switch node.Command {
		case 4: // create database
			if !q.isDatabaseAllowed(node.Op.Name.String()) {
				return false, q.notAllowed(node.Op.Name.String())
			}
		default:
			if !q.isDatabaseAllowed(node.Op.Qualifier.String()) {
				return false, q.notAllowed(node.Op.Qualifier.String())
			}
		}
	case *sqlparser.ShowBasic:
		if !q.isDatabaseAllowed(node.DbName.String()) {
			return false, q.notAllowed(node.DbName.String())
		}
	case *sqlparser.ShowOther:
		if strings.EqualFold(node.Command, "create user") || strings.EqualFold(node.Command, "grants") {
			if !q.isDatabaseAllowed("mysql") {
				return false, fmt.Errorf("database mysql is not allowed")
			}
		}
	case *sqlparser.PrepareStmt:
		q.stmtType = "PREPARE"
		if !q.isDatabaseAllowed(q.database) {
			return false, fmt.Errorf("database %s is not allowed", q.database)
		}

		var innerStmt string
		switch node := node.Statement.(type) {
		case *sqlparser.Literal:
			innerStmt = string(node.Val)
		case *sqlparser.Variable:
			if q, ok := q.handler.variables[node.Name.Lowered()]; !ok {
				return false, fmt.Errorf("variable %s is not allowed", node.Name.Lowered())
			} else {
				innerStmt = q
			}
		default:
			return false, fmt.Errorf("invalid prepare statement type %T", node)
		}

		allowed, _, err := q.handler.isAllowed(innerStmt)
		if err != nil {
			return false, err
		}

		if !allowed {
			return false, fmt.Errorf("prepare statement %s is not allowed", innerStmt)
		}
	case *sqlparser.ExecuteStmt:
		q.stmtType = "EXECUTE"
		if !q.isDatabaseAllowed(q.database) {
			return false, fmt.Errorf("database %s is not allowed", q.database)
		}

	case *sqlparser.DeallocateStmt:
		q.stmtType = "DEALLOCATE PREPARE"
		if !q.isDatabaseAllowed(q.database) {
			return false, fmt.Errorf("database %s is not allowed", q.database)
		}
	case *sqlparser.Set:
		for _, expr := range node.Exprs {
			switch e := expr.Expr.(type) {
			case *sqlparser.Literal:
				q.handler.variables[expr.Var.Name.Lowered()] = string(e.Val)
			case *sqlparser.FuncExpr:
				funcName := e.Name.Lowered()
				switch funcName {
				case "concat":
					var concatenatedValue strings.Builder
					for _, e := range e.Exprs {
						switch e := e.(type) {
						case *sqlparser.Literal:
							switch e.Type {
							case sqlparser.HexNum:
								bytes, err := hex.DecodeString(e.Val[2:])
								if err != nil {
									return false, fmt.Errorf("failed to decode hex value %s: %w", e.Val, err)
								}
								concatenatedValue.Write(bytes)
							default:
								concatenatedValue.WriteString(string(e.Val))
							}
						default:
							return false, fmt.Errorf("unsupported expression type %T in CONCAT function", e)
						}
					}
					q.handler.variables[expr.Var.Name.Lowered()] = concatenatedValue.String()
				default:
					return false, fmt.Errorf("unsupported function %s", funcName)
				}
			default:
				return false, fmt.Errorf("unsupported set statement type %T", expr.Expr)
			}
		}
	}
	return true, nil
}

func (q *queryValidator) isDatabaseAllowed(database string) bool {
	if q.permissions.AllowedDatabases == nil {
		q.allowedDatabaseFound = true
		return true
	}

	if database == "" {
		database = q.database
	}

	for _, s := range *q.permissions.AllowedDatabases {
		if s.Database == "*" || s.Database == database || database == "" {
			if s.AllowedQueryTypes == nil {
				q.allowedDatabaseFound = true
				return true
			}

			// implicit USE permission, if database is allowed also allow USE statement to switch to that database
			if strings.EqualFold("USE", q.stmtType) {
				q.allowedDatabaseFound = true
				return true
			}

			for _, queryType := range *s.AllowedQueryTypes {
				switch queryType {
				case "ReadWrite":
					switch q.stmtType {
					case "SELECT", "INSERT", "UPDATE", "REPLACE", "DELETE", "DDL", "BEGIN", "ROLLBACK", "COMMIT", "REVERT", "LOCK_TABLES", "UNLOCK_TABLES", "SHOW", "SET", "EXPLAIN", "ANALYZE", "RELEASE", "PREPARE", "EXECUTE", "DEALLOCATE PREPARE":
						q.allowedDatabaseFound = true
						return true
					}
					return true
				case "ReadOnly":
					switch q.stmtType {
					case "SELECT", "SHOW", "SET", "EXPLAIN", "PREPARE", "EXECUTE", "DEALLOCATE PREPARE":
						q.allowedDatabaseFound = true
						return true
					}
				default:
					if strings.EqualFold(queryType, q.stmtType) {
						q.allowedDatabaseFound = true
						return true
					}
				}
			}
		}
	}

	return false
}

func (h *mysqlLocalHandler) record(command string, status *uint16, result *string, duration int64, rows *int64, affectedRows *uint64) {
	if !h.socket.RecordingEnabled {
		return
	}

	h.recordingChan <- message{
		Time:         time.Now().UnixMilli(),
		Database:     h.database,
		Command:      command,
		Status:       status,
		Result:       result,
		Duration:     duration,
		Rows:         rows,
		AffectedRows: affectedRows,
	}
}

func (h *mysqlLocalHandler) ErrorEvent(eventType string, message string) error {
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

func (h *mysqlLocalHandler) CreateSessionEvent(e models.SessionEvent) error {
	return h.border0API.CreateSessionEvent(e)
}
