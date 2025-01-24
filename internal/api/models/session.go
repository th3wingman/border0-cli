package models

import "time"

type ResultValue string

const (
	ResultSuccess ResultValue = "success"
	ResultDenied  ResultValue = "denied"
)

type SessionUpdate struct {
	SessionKey     string
	Socket         *Socket
	UserData       string
	Result         ResultValue
	AuthInfoFailed string
}

type SessionCreateResult struct {
	SessionKey string
	SshTicket  []byte
}

type Session struct {
	SessionID   string
	StartTime   *time.Time
	EndTime     *time.Time
	LastSeen    *time.Time
	Email       string
	LogType     string
	SocketID    string
	ServerName  string
	ServerPort  string
	ClientIP    string
	ClientPort  string
	SessionData string
	SessionKey  string
	Killed      bool
	KilledAt    *time.Time
	Result      string
	AuthInfo    string
	Metadata    []byte
	EntityUUID  string
}

type SessionEvent struct {
	SessionKey string
	Socket     *Socket
	Type       string
	Status     string
	Metadata   string
}
