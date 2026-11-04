package artifacts

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// TrufflehogFinding is one line of `trufflehog --json` output. Raw secret
// values are not decoded, so they cannot end up in a table or a log.
type TrufflehogFinding struct {
	SourceName     string          `json:"SourceName"`
	DetectorName   string          `json:"DetectorName"`
	DecoderName    string          `json:"DecoderName"`
	Verified       bool            `json:"Verified"`
	SourceMetadata json.RawMessage `json:"SourceMetadata"`
}

// Location is file:line, or the best location the source metadata has.
func (f TrufflehogFinding) Location() string {
	var meta struct {
		Data map[string]struct {
			File       string `json:"file"`
			Path       string `json:"path"`
			Line       int    `json:"line"`
			Commit     string `json:"commit"`
			Link       string `json:"link"`
			Repository string `json:"repository"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(f.SourceMetadata, &meta); err != nil {
		return "-"
	}
	for _, d := range meta.Data {
		file := d.File
		if file == "" {
			file = d.Path
		}
		switch {
		case file != "" && d.Line > 0:
			return fmt.Sprintf("%s:%d", file, d.Line)
		case file != "":
			return file
		case d.Link != "":
			return d.Link
		case d.Repository != "":
			return d.Repository
		}
	}
	return "-"
}

// Commit is the git commit of the finding, or "-".
func (f TrufflehogFinding) Commit() string {
	var meta struct {
		Data map[string]struct {
			Commit string `json:"commit"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(f.SourceMetadata, &meta); err != nil {
		return "-"
	}
	for _, d := range meta.Data {
		if d.Commit != "" {
			if len(d.Commit) > 12 {
				return d.Commit[:12]
			}
			return d.Commit
		}
	}
	return "-"
}

// DecodeTrufflehog reads newline-delimited trufflehog JSON. A JSON array of
// the same objects is also accepted. Lines that are not finding objects are
// skipped.
func DecodeTrufflehog(content []byte) ([]TrufflehogFinding, error) {
	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return nil, nil
	}
	if content[0] == '[' {
		var findings []TrufflehogFinding
		if err := json.Unmarshal(content, &findings); err != nil {
			return nil, err
		}
		return findings, nil
	}
	var findings []TrufflehogFinding
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var f TrufflehogFinding
		if err := json.Unmarshal(line, &f); err != nil {
			return nil, fmt.Errorf("trufflehog line: %w", err)
		}
		if strings.TrimSpace(f.DetectorName) == "" {
			continue
		}
		findings = append(findings, f)
	}
	return findings, scanner.Err()
}

func isTrufflehogLine(line []byte) bool {
	var probe struct {
		DetectorName   string          `json:"DetectorName"`
		SourceMetadata json.RawMessage `json:"SourceMetadata"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return false
	}
	return probe.DetectorName != "" && len(probe.SourceMetadata) > 0
}
