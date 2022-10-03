package artifact

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestNewAsset(t *testing.T) {
	content := "One fish two fish, red fish blue fish"
	buf := new(bytes.Buffer)
	buf.WriteString(content)

	asset, err := NewAsset("some-file.some", buf)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Digest: %s\n", hex.EncodeToString(asset.Digest))
	t.Logf("Content: %s\n", string(asset.Content))

	if strings.Compare(content, string(asset.Content)) != 0 {
		t.Logf("Digest: %s\n", string(asset.Digest))
		t.Logf("Content: %s\n", string(asset.Content))
		t.Fatal("Content passed and content parsed does not match")
	}

	// Provoke error
	t.Run("Mock Reader Error", func(t *testing.T) {
		if _, err := NewAsset("", new(badReader)); err == nil {
			t.Fatal("Expected error for bad reader, got nil")
		}
	})

}

type badReader struct{}

func (b badReader) Read(_ []byte) (int, error) {
	return 0, errors.New("mock error")
}
