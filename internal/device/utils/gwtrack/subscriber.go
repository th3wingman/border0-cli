package gwtrack

import "github.com/google/uuid"

// subscriber is the default Subscriber implementation.
type subscriber struct {
	subscriberID string
	channel      <-chan *Update
	tracker      *tracker
}

// newSubscriber returns a newly initialized
// subscriber for the given tracker.
func newSubscriber(t *tracker) Subscriber {
	subscriberID := uuid.NewString()
	channel := make(chan *Update)
	t.subscribers.Store(subscriberID, channel)
	return &subscriber{
		tracker:      t,
		channel:      channel,
		subscriberID: subscriberID,
	}
}

// Close closes the subscriber and frees associated resources.
func (s *subscriber) Close() {
	c, loaded := s.tracker.subscribers.LoadAndDelete(s.subscriberID)
	if loaded {
		close(c)
	}
}

// C returns the subscriber's channel.
func (s *subscriber) C() <-chan *Update {
	return s.channel
}
