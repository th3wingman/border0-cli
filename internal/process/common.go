package process

// Parameters represents process parameters.
type Parameters struct {
	UID    int
	GID    int
	User   string // NOT USED
	Groups []int
}
