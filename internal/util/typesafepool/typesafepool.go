package typesafepool

import "sync"

// Pool is a type-safe version of sync.Pool.
type Pool[T any] interface {
	Get() T
	Put(T)
}

// pool is the default Pool implementation.
type pool[T any] struct {
	inner sync.Pool
}

// New returns a new type-safe pool whose "New"
// function is passed as an argument.
func New[T any](fn func() T) Pool[T] {
	return &pool[T]{inner: sync.Pool{New: func() any { return fn() }}}
}

// Get retrieves an available element from the pool.
func (p *pool[T]) Get() T { return p.inner.Get().(T) }

// Put returns a no-longer-needed element to the pool.
func (p *pool[T]) Put(t T) { p.inner.Put(t) }
