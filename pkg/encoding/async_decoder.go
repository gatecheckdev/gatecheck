package encoding

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

const GenericFileType string = "Generic"

type WriterDecoder interface {
	io.Writer
	Decode() (any, error)
	DecodeFrom(r io.Reader) (any, error)
	FileType() string
}

type AsyncDecoder struct {
	bytes.Buffer
	decoders []WriterDecoder
	fileType string
}

func NewAsyncDecoder(decs ...WriterDecoder) *AsyncDecoder {
	decoder := new(AsyncDecoder)
	decoder.decoders = decs
	return decoder
}

func (d *AsyncDecoder) WithDecoders(decs ...WriterDecoder) *AsyncDecoder {
	d.decoders = decs
	return d
}

func (d *AsyncDecoder) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIO, err)
	}
	return d.Decode()
}

func (d *AsyncDecoder) Decode() (any, error) {
	if len(d.decoders) == 0 {
		return nil, fmt.Errorf("%w: no decoders provided", ErrEncoding)
	}

	objChan := make(chan any)
	doneChan := make(chan struct{})
	var wg sync.WaitGroup
	var once sync.Once

	// Non desctructive reader
	reader := bytes.NewReader(d.Bytes())
	for i := range d.decoders {
		wg.Add(1)
		_, err := reader.WriteTo(d.decoders[i])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrIO, err)
		}
		reader.Seek(0, 0)
		go func(decoder WriterDecoder) {
			v, err := decoder.Decode()

			if err != nil {
				wg.Done()
				return
			}
			once.Do(func() { d.fileType = decoder.FileType() })
			objChan <- v
		}(d.decoders[i])
	}

	go func(c chan struct{}, wg *sync.WaitGroup) {
		wg.Wait()
		c <- struct{}{}
	}(doneChan, &wg)

	select {
	// All decoders finished before one was successful
	case <-doneChan:
		d.fileType = GenericFileType
		return nil, fmt.Errorf("%w: All decoders failed", ErrEncoding)
	// One of the decoders were able to successfully decode
	case obj := <-objChan:
		return obj, nil
	}
}

// FileType MUST be run after Decode to get the filetype, otherwise it will return '?'
func (d *AsyncDecoder) FileType() string {
	if d.fileType == "" {
		return "?"
	}
	return d.fileType
}
