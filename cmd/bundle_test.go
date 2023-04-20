package cmd

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
)

func TestNewBundleCmd(t *testing.T) {

	t.Run("file-access-error", func(t *testing.T) {
		outFile := path.Join(t.TempDir(), "bundle.gatecheck")
		commandString := fmt.Sprintf("bundle -o %s %s", outFile, fileWithBadPermissions(t))
		_, err := Execute(commandString, CLIConfig{})
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
	})

	t.Run("bad-output-file", func(t *testing.T) {
		commandString := fmt.Sprintf("bundle -o %s %s", fileWithBadPermissions(t), fileWithBadPermissions(t))
		_, err := Execute(commandString, CLIConfig{})
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
	})

	t.Run("bad-decode", func(t *testing.T) {
		commandString := fmt.Sprintf("bundle -vo %s %s", fileWithBadJSON(t), fileWithBadJSON(t))
		_, err := Execute(commandString, CLIConfig{})
		if errors.Is(err, ErrorEncoding) != true {
			t.Fatal(err)
		}
	})

	t.Run("bad-permission", func(t *testing.T) {
		outFile := path.Join(t.TempDir(), "bundle.gatecheck")
		commandString := fmt.Sprintf("bundle -vo %s %s", outFile, fileWithBadPermissions(t))
		_, err := Execute(commandString, CLIConfig{})
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
	})

	t.Run("new-bundle", func(t *testing.T) {
		outFile := path.Join(t.TempDir(), "bundle.gatecheck")
		targetFile := path.Join(t.TempDir(), "random-1.file")
		b := make([]byte, 1000)

		_, _ = rand.Read(b)
		if err := os.WriteFile(targetFile, b, 0664); err != nil {
			t.Fatal(err)
		}
		commandString := fmt.Sprintf("bundle -vo %s %s", outFile, targetFile)
		_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 2})
		if err != nil {
			t.Fatal(err)
		}

		// Check bundle for the artifact
		postOutFile := MustOpen(outFile, t.Fatal)
		bun := artifact.DecodeBundle(postOutFile)
		genericFile, ok := bun.Generic["random-1.file"]
		if !ok {
			t.Fatal("Could not extract generic file")
		}

		if len(genericFile.Content) != 1000 {
			t.Fatal("Invalid decoded file size")
		}

		t.Run("print-test", func(t *testing.T) {
			commandString := fmt.Sprintf("print %s", outFile)
			output, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 2})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(output, "random-1.file") != true {
				t.Log(output)
				t.Fatal("unexpected content")
			}
		})

		t.Run("existing-bundle", func(t *testing.T) {
			secondFile := path.Join(t.TempDir(), "random-2.file")
			b := make([]byte, 2000)
			_, _ = rand.Read(b)
			if err := os.WriteFile(secondFile, b, 0664); err != nil {
				t.Fatal(err)
			}
			commandString := fmt.Sprintf("bundle -vo %s %s", outFile, secondFile)
			output, err := Execute(commandString, CLIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Log(output)
		})

		t.Run("empty-file", func(t *testing.T) {
			emptyFile := path.Join(t.TempDir(), "empty.file")
			if err := os.WriteFile(emptyFile, []byte{}, 0664); err != nil {
				t.Fatal(err)
			}
			commandString := fmt.Sprintf("bundle -vo %s %s", outFile, emptyFile)
			output, err := Execute(commandString, CLIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Log(output)
		})

	})

}
