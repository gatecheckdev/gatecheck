package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path"
)

var ErrorFileAccess = errors.New("file access error")
var ErrorFileExists = errors.New("file already exists")
var ErrorFileNotExists = errors.New("file does not exists")
var ErrorDecode = errors.New("error decoding a file")
var ErrorEncode = errors.New("error encoding a file")
var ErrorValidation = errors.New("report failed validation")

type Decoder interface {
	Decode(v any) error
}

// Open is a wrapper function for os.Open with cmd specific errors
func Open(filename string) (io.Reader, error) {
	if filename == "" {
		return nil, fmt.Errorf("%w : %v", ErrorFileAccess, errors.New("invalid filename"))
	}

	if _, err := os.Stat(filename); err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileNotExists, err)
	}

	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}
	return f, nil
}

// OpenOrCreateInDirectory can be used to create new files by passing a filename or the name of a directory.
// If the name of an existing directory is passed, a new file will be created in that directory
func OpenOrCreateInDirectory(directoryOrFilename string, FilenameIfDirectory string) (io.ReadWriter, error) {
	fileInfo, err := os.Stat(directoryOrFilename)
	// Stat Error could be that the file doesn't exist or there was an issue access the file like permissions
	// Let the OpenOrCreate function handle errors or file creation
	// This function can't create directories because there's no way to know from a string if it's a dir or file name
	if err != nil {
		return OpenOrCreate(directoryOrFilename)
	}

	// If a directory was passed, append the FilenameIfDirectory to the path and call the OpenOrCreate Function
	if fileInfo.IsDir() {
		return OpenOrCreate(path.Join(directoryOrFilename, FilenameIfDirectory))
	}

	// Edge Case: If a file or directory was passed but errored on stat (probably permissions or bad descriptor)
	return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
}

// OpenOrCreate if the file doesn't exist it will be created
func OpenOrCreate(filename string) (io.ReadWriter, error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}
	return f, nil
}

// OpenAll can be used to open multiple files at once
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

type FileType int

const (
	JSON FileType = iota
	YAML FileType = iota
)

// OpenAndDecode opens a file and decodes it into the desired object
func OpenAndDecode[T any](filename string, fileType FileType) (*T, error) {
	// Open the File
	var err error
	f, err := Open(filename)
	if err != nil {
		return nil, err
	}

	// Decode based on file type
	obj := new(T)
	switch fileType {
	case JSON:
		err = json.NewDecoder(f).Decode(obj)
	case YAML:
		err = yaml.NewDecoder(f).Decode(obj)
	}

	if err != nil {
		return obj, fmt.Errorf("%w : %v", ErrorDecode, err)
	}

	// Return the object
	return obj, nil
}

// OpenAndDecodeOrCreate will return a new object if the file did not exist. Will not write the file
func OpenAndDecodeOrCreate[T any](filename string, fileType FileType) (*T, error) {
	obj, err := OpenAndDecode[T](filename, fileType)
	// The object could not be decoded from the provided file
	if err != nil {
		obj = new(T)
		// File does exist but there was an issue with file access or the decoding of that file
		if _, statErr := os.Stat(filename); errors.Is(statErr, os.ErrNotExist) != true {
			// Let the caller decide to supress the error and accept the new object
			return obj, fmt.Errorf("%w : %v", ErrorFileAccess, err)
		}
		// Supress a not exists error
		err = nil
	}
	return obj, err
}

// OpenAndEncode opens a file and encodes the object based in the fileType format
func OpenAndEncode(filename string, fileType FileType, object any) error {
	// Open the file for writing
	var err error
	f, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}

	// Encode the object
	switch fileType {
	case JSON:
		err = json.NewEncoder(f).Encode(object)
	case YAML:
		err = yaml.NewEncoder(f).Encode(object)
	}

	if err != nil {
		return fmt.Errorf("%w : %v", ErrorEncode, err)
	}

	return nil
}
