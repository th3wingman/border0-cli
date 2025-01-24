package stun

import (
	"sync"

	"github.com/pion/stun/v3"
)

const txChannelBufferSize = 5

type transaction struct {
	mu      *sync.Mutex
	ch      chan *stun.Message
	expired bool
}

func newTransaction() *transaction {
	return &transaction{
		mu:      &sync.Mutex{},
		ch:      make(chan *stun.Message, txChannelBufferSize),
		expired: false,
	}
}

func (tx *transaction) receive(resp *stun.Message) bool {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if !tx.expired {
		select {
		case tx.ch <- resp:
			return true
		default:
			// Channel is full, cannot receive. This is important
			// to avoid the receive function from blocking when
			// the channel has no reader yet.
			return false
		}
	}

	return false
}

func (tx *transaction) expire() {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if !tx.expired {
		close(tx.ch)
		tx.expired = true
	}
}
