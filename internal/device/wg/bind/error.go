package bind

// suppressedError represents an error being suppressed.
type suppressedError struct{ inner error }

// Error implements the error interface.
func (e *suppressedError) Error() string { return e.inner.Error() }
