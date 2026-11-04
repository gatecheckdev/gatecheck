package main

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/gatecheckdev/gatecheck/internal/bootstrap"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
)

type exitStub int

func (e exitStub) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitStub) ExitCode() int { return int(e) }

func TestStatus(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{exitStub(4), 4},
		{fmt.Errorf("%w: semgrep", gatecheck.ErrValidationFailure), 1},
		{errors.New("boom"), 2},
		{os.ErrNotExist, 2},
		{bootstrap.ErrNotInstalled, 2},
		{fmt.Errorf("%w: kev", gatecheck.ErrExternalData), 3},
		{errors.Join(fmt.Errorf("%w: a", gatecheck.ErrValidationFailure), fmt.Errorf("%w: b", gatecheck.ErrExternalData)), 1},
	}
	for _, tc := range cases {
		if got := status(tc.err); got != tc.want {
			t.Errorf("status(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}
