package cmd

import (
	"bytes"
	"testing"
)

func Test_VersionCmd(t *testing.T) {
	actual := new(bytes.Buffer)
	RootCmd.SetOut(actual)
	RootCmd.SetErr(actual)
	RootCmd.SetArgs([]string{"version"})
	err := RootCmd.Execute()

	t.Log(actual)
	if err != nil {
		t.Fatal("No error expected for root command")
	}

}

func Test_RootCmd(t *testing.T) {
	actual := new(bytes.Buffer)
	RootCmd.SetArgs([]string{})
	t.Log(actual)
	if err := RootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
}
