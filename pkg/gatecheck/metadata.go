package gatecheck

import (
	"fmt"
	"io"
)

// ApplicationMetadata ...
type ApplicationMetadata struct {
	CLIVersion     string
	GitCommit      string
	BuildDate      string
	GitDescription string
	Platform       string
	GoVersion      string
	Compiler       string
}

func (m ApplicationMetadata) String() string {
	return fmt.Sprintf(`CLIVersion:     %s
GitCommit:      %s
Build Date:     %s
GitDescription: %s
Platform:       %s
GoVersion:      %s
Compiler:       %s
`,
		m.CLIVersion, m.GitCommit, m.BuildDate, m.GitDescription,
		m.Platform, m.GoVersion, m.Compiler)
}

func (m ApplicationMetadata) WriteTo(w io.Writer) (int64, error) {
	n, err := fmt.Fprintf(w, "%s\n\n%s", gatecheckLogo, m)
	return int64(n), err
}
