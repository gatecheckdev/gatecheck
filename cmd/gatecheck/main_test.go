package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
)

type exitStub int

func (e exitStub) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitStub) ExitCode() int { return int(e) }

func TestStatus(t *testing.T) {
	if status(nil) != exitOk {
		t.Fatal("nil")
	}
	if status(exitStub(4)) != 4 {
		t.Fatal("passthrough")
	}
	if status(fmt.Errorf("%w: semgrep", gatecheck.ErrValidationFailure)) != exitValidationFail {
		t.Fatal("validation")
	}
	if status(errors.New("boom")) != exitSystemFail {
		t.Fatal("system")
	}
}
