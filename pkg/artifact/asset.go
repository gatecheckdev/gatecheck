package artifact

import (
	"bytes"
	"crypto/sha256"
	"io"
)

type Asset struct {
	Label   string `json:"label"`
	Digest  []byte `json:"scanReportDigest"`
	Content []byte `json:"-"`
}

func NewAsset(label string, r io.Reader) (*Asset, error) {
	hashWriter := sha256.New()
	buf := new(bytes.Buffer)

	// Hash the file
	multiWriter := io.MultiWriter(hashWriter, buf)

	if _, err := io.Copy(multiWriter, r); err != nil {
		return nil, err
	}

	return &Asset{
		Label:   label,
		Digest:  hashWriter.Sum(nil),
		Content: buf.Bytes(),
	}, nil
}
