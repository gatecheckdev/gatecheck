package cmd

import (
	"bytes"
	"github.com/gatecheckdev/gatecheck/pkg/exporter/defectDojo"
	"testing"
)

func Test_VersionCmd(t *testing.T) {
	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{}, mockService{})
	command.SetOut(actual)
	command.SetErr(actual)
	command.SetArgs([]string{"version"})
	err := command.Execute()

	t.Log(actual)
	if err != nil {
		t.Fatal("No error expected for root command")
	}

}

func Test_RootCmd(t *testing.T) {
	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{}, mockService{})
	command.SetArgs([]string{})
	t.Log(actual)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
}
