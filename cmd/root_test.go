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
	//if strings.Compare(actual.String(), expected) != 0 {
	//	t.Fatalf("Expected -> '%v' Got -> '%v'", expected, actual.String())
	//}
}
