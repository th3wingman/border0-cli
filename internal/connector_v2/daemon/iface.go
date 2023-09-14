package daemon

import (
	"github.com/kardianos/service"
)

// daemon represents the Border0 connector daemon.
type daemon struct {
	stop chan struct{}
}

// ensure daemon implements service.Interface at compile time.
var _ service.Interface = (*daemon)(nil)

// Start signals the start of the daemon.
// It must be non-blocking.
func (d *daemon) Start(s service.Service) error {
	d.stop = make(chan struct{})
	go d.run()
	return nil
}

// run manages the daemon's runtime.
// It must block until stop is called.
func (d *daemon) run() {
	<-d.stop
	return
}

// Stop signals the stopping of the daemon.
// It must be non-blocking.
func (d *daemon) Stop(s service.Service) error {
	close(d.stop)
	return nil
}
