package io

import (
	"io"
	"os"

	"github.com/gatecheckdev/gatecheck/internal/log"
)

// LazyReader is a wrapper for *os.File which opens the file on read.
// Used for the CLI which has a common method for handling errors.
// It will also auto close the file once EOF is reached.
type LazyReader struct {
	f        *os.File
	filename string
}

func NewLazyReader(filename string) *LazyReader {
	return &LazyReader{filename: filename}
}

func (r *LazyReader) Read(b []byte) (int, error) {
	if r.f != nil {
		n, err := r.f.Read(b)
		if err == io.EOF {
			return n, closeEOF(r.f)
		}
		return n, err
	}

	log.Infof("LazyReader opening file '%s'", r.filename)
	f, err := os.Open(r.filename)
	if err != nil {
		return 0, err
	}
	r.f = f
	return r.Read(b)
}

// Will close and return EOF if no close errors
func closeEOF(f io.Closer) error {
	if err := f.Close(); err != nil {
		return err
	}
	return io.EOF
}
