package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var ErrorFileAccess = errors.New("file access error")
var ErrorFileExists = errors.New("file already exists")
var ErrorFileNotExists = errors.New("file does not exists")
var ErrorConfig = errors.New("error decoding the configuration file")
var ErrorDecode = errors.New("error decoding a file")
var ErrorValidation = errors.New("report failed validation")

func Open(filename string) (io.Reader, error) {
	if _, err := os.Stat(filename); err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileNotExists, err)
	}

	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}
	return f, nil
}

func OpenAll(filenames ...string) ([]io.Reader, error) {
	files := make([]io.Reader, len(filenames))
	for i, name := range filenames {
		f, err := Open(name)
		if err != nil {
			return nil, err
		}
		files[i] = f
	}
	return files, nil
}
