package artifacts

import (
	"github.com/gatecheckdev/gatecheck/pkg/format"
)

type GitLeaksReportMin []GitleaksFinding

func (r *GitLeaksReportMin) Count() int {
	n := 0
	for range *r {
		n++
	}
	return n
}

type GitleaksFinding struct {
	RuleID    string `json:"RuleID"`
	File      string `json:"File"`
	Commit    string `json:"Commit"`
	StartLine int    `json:"StartLine"`
}

func (f *GitleaksFinding) FileShort() string {
	return format.Summarize(f.File, 50, format.ClipMiddle)
}

func (f *GitleaksFinding) CommitShort() string {
	return f.Commit[:8]
}
