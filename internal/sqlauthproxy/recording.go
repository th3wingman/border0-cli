package sqlauthproxy

// message format for database socket session recordings
type message struct {
	Time         int64   `json:"time"`
	Database     string  `json:"database"`
	Command      string  `json:"command"`
	Status       *uint16 `json:"status"`
	Duration     int64   `json:"duration"`
	Rows         *int64  `json:"rows"`
	AffectedRows *uint64 `json:"affected_rows"`
	Result       *string `json:"result"`
}
