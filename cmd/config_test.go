package cmd

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"github.com/gatecheckdev/gatecheck/pkg/exporter/defectDojo"
	"os"
	"path"
	"testing"
)

func Test_ConfigInitCmd(t *testing.T) {
	// Provoke an error with improper file name

	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	t.Run("file-access", func(t *testing.T) {
		command.SetArgs([]string{"config", "init", CreateMockFile(t, NoPermissions)})
		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected File Access error, %v", err)
		}
		command.SetArgs([]string{"config", "init", CreateMockFile(t, BadDescriptor)})
		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected File Access error, %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		tempDir := t.TempDir()

		command.SetArgs([]string{"config", "init", tempDir})
		t.Log(tempDir)
		err := command.Execute()
		if err != nil {
			t.Fatal(err)
		}

		fileInfo, err := os.Stat(path.Join(tempDir, "gatecheck.yaml"))
		if err != nil {
			t.Error(fileInfo)
			t.Fatal(err)
		}

		if fileInfo.Size() < 70 {
			t.Fatal("File size is unexpectedly small")
		}
	})

	t.Run("file", func(t *testing.T) {
		tempDir := path.Join(t.TempDir(), "custom-name.yaml")
		command.SetArgs([]string{"config", "init", tempDir})
		err := command.Execute()
		if err != nil {
			t.Fatal(err)
		}

		fileInfo, err := os.Stat(tempDir)
		if err != nil {
			t.Fatal(err)
		}

		if fileInfo.Size() < 70 {
			t.Fatal("File size is unexpectedly small")
		}
	})

	t.Run("file with project name", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "custom-name.yaml")
		command.SetArgs([]string{"config", "init", fPath, "test project name"})
		err := command.Execute()
		if err != nil {
			t.Fatal(err)
		}

		_, err = os.Stat(fPath)
		if err != nil {
			t.Fatal(err)
		}

		c, err := OpenAndDecode[config.Config](fPath, YAML)
		if c.ProjectName != "test project name" {
			t.Logf("%+v\n", c)
			t.Fatal("Expected project name to be 'test project name'")
		}

	})
}
