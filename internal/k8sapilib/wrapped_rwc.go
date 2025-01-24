package k8sapilib

import "io"

// wrappedRWC represents an io.ReadWriteCloser implementation.
type wrappedRWC struct {
	reader    io.Reader
	writer    io.Writer
	closer    io.Closer
	postclose func()
}

// newTeeWrappedRWC returns a io.ReadWriteCloser where all reads are written to the given writer.
func newTeeWrappedRWC(rwc io.ReadWriteCloser, writer io.Writer, postclose func()) io.ReadWriteCloser {
	return &wrappedRWC{
		reader:    io.TeeReader(rwc, writer),
		writer:    rwc,
		closer:    rwc,
		postclose: postclose,
	}
}

// Read reads data from the rwc onto the given buffer.
func (rwc *wrappedRWC) Read(p []byte) (int, error) {
	return rwc.reader.Read(p)
}

// Write writes data from the given buffer to the rwc.
func (rwc *wrappedRWC) Write(p []byte) (int, error) {
	return rwc.writer.Write(p)
}

// Close closes the rwc.
func (rwc *wrappedRWC) Close() error {
	defer rwc.postclose()
	return rwc.closer.Close()
}
