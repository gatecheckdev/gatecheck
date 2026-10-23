package artifacts

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ReportKind is a report type gatecheck can list or validate.
type ReportKind string

const (
	KindUnknown   ReportKind = ""
	KindGrype     ReportKind = "grype"
	KindCycloneDX ReportKind = "cyclonedx"
	KindSemgrep   ReportKind = "semgrep"
	KindGitleaks  ReportKind = "gitleaks"
	KindSyft      ReportKind = "syft"
	KindTrivy     ReportKind = "trivy"
	KindOSV       ReportKind = "osv"
	KindSARIF     ReportKind = "sarif"
	KindBundle    ReportKind = "bundle"
	KindLCOV      ReportKind = "lcov"
	KindClover    ReportKind = "clover"
	KindCobertura ReportKind = "cobertura"
	// KindCoverage means the filename selected coverage, and the format is not known yet.
	KindCoverage ReportKind = "coverage"
)

// IsCoverage reports whether the kind is a coverage file.
func (k ReportKind) IsCoverage() bool {
	switch k {
	case KindLCOV, KindClover, KindCobertura, KindCoverage:
		return true
	default:
		return false
	}
}

// Detect identifies a report from its bytes.
// KindUnknown means the contents are ambiguous and the caller should use the filename.
func Detect(content []byte) ReportKind {
	content = bytes.TrimSpace(bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF}))
	if len(content) == 0 {
		return KindUnknown
	}
	// Gzip is a bundle, or it is not a report. Bundle detection lives with the caller.
	if bytes.HasPrefix(content, []byte{0x1f, 0x8b}) {
		return KindUnknown
	}
	if content[0] == '{' || content[0] == '[' {
		return detectJSON(content)
	}
	if looksXML(content) {
		return detectXMLCoverage(content)
	}
	if looksLCOV(content) {
		return KindLCOV
	}
	return KindUnknown
}

func detectJSON(content []byte) ReportKind {
	if content[0] == '[' {
		return detectGitleaks(content)
	}

	var head sniff
	if err := json.Unmarshal(content, &head); err != nil {
		return KindUnknown
	}
	return classifyObject(head)
}

type sniff struct {
	BomFormat  string          `json:"bomFormat"`
	SchemaURI  string          `json:"$schema"`
	Version    any             `json:"version"`
	Runs       json.RawMessage `json:"runs"`
	Matches    json.RawMessage `json:"matches"`
	Descriptor struct {
		Name string `json:"name"`
	} `json:"descriptor"`
	Results       json.RawMessage `json:"results"`
	Errors        json.RawMessage `json:"errors"`
	Paths         json.RawMessage `json:"paths"`
	SchemaVersion any             `json:"SchemaVersion"`
	ArtifactType  string          `json:"ArtifactType"`
	TrivyResults  json.RawMessage `json:"Results"`
	Schema        struct {
		URL string `json:"url"`
	} `json:"schema"`
}

func classifyObject(s sniff) ReportKind {
	if strings.EqualFold(strings.TrimSpace(s.BomFormat), "CycloneDX") {
		return KindCycloneDX
	}
	if isSarif(s) {
		return KindSARIF
	}
	switch strings.ToLower(strings.TrimSpace(s.Descriptor.Name)) {
	case "grype":
		return KindGrype
	case "syft":
		return KindSyft
	}
	if strings.Contains(strings.ToLower(s.Schema.URL), "anchore/syft") {
		return KindSyft
	}
	if isSemgrep(s) {
		return KindSemgrep
	}
	if isGrypeMatches(s.Matches) {
		return KindGrype
	}
	if isTrivy(s) {
		return KindTrivy
	}
	if isOSV(s) {
		return KindOSV
	}
	return KindUnknown
}

func isTrivy(s sniff) bool {
	if _, ok := s.SchemaVersion.(float64); !ok {
		return false
	}
	if strings.TrimSpace(s.ArtifactType) != "" {
		return true
	}
	return isJSONArray(s.TrivyResults)
}

func isOSV(s sniff) bool {
	if !isJSONArray(s.Results) || jsonArrayEmpty(s.Results) {
		return false
	}
	var rows []struct {
		Packages json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(s.Results, &rows); err != nil || len(rows) == 0 {
		return false
	}
	return isJSONArray(rows[0].Packages)
}

func isSarif(s sniff) bool {
	version, ok := s.Version.(string)
	if !ok || version != "2.1.0" {
		return false
	}
	if isJSONArray(s.Runs) {
		return true
	}
	schema := strings.ToLower(s.SchemaURI)
	if !strings.Contains(schema, "sarif") {
		return false
	}
	trimmed := bytes.TrimSpace(s.Runs)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

func isSemgrep(s sniff) bool {
	if !isJSONArray(s.Results) {
		return false
	}
	if !jsonArrayEmpty(s.Results) {
		var rows []struct {
			CheckID string `json:"check_id"`
		}
		if err := json.Unmarshal(s.Results, &rows); err != nil || len(rows) == 0 {
			return false
		}
		return rows[0].CheckID != ""
	}
	// An empty results array is Semgrep when the rest of the document has Semgrep's other keys.
	return isJSONArray(s.Errors)
}

func isGrypeMatches(raw json.RawMessage) bool {
	if !isJSONArray(raw) || jsonArrayEmpty(raw) {
		return false
	}
	var rows []struct {
		Vulnerability json.RawMessage `json:"vulnerability"`
		Artifact      json.RawMessage `json:"artifact"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) == 0 {
		return false
	}
	return len(bytes.TrimSpace(rows[0].Vulnerability)) > 0 && len(bytes.TrimSpace(rows[0].Artifact)) > 0
}

func detectGitleaks(content []byte) ReportKind {
	dec := json.NewDecoder(bytes.NewReader(content))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('[') || !dec.More() {
		return KindUnknown
	}
	var first map[string]json.RawMessage
	if err := dec.Decode(&first); err != nil {
		return KindUnknown
	}
	if _, ok := first["RuleID"]; !ok {
		return KindUnknown
	}
	_, file := first["File"]
	_, commit := first["Commit"]
	_, fingerprint := first["Fingerprint"]
	if file || commit || fingerprint {
		return KindGitleaks
	}
	return KindUnknown
}

func looksXML(content []byte) bool {
	return bytes.HasPrefix(content, []byte("<?xml")) || bytes.HasPrefix(content, []byte("<"))
}

func detectXMLCoverage(content []byte) ReportKind {
	lower := bytes.ToLower(content)
	if bytes.Contains(lower, []byte("clover=")) || bytes.Contains(lower, []byte("<clover")) {
		return KindClover
	}
	if bytes.Contains(lower, []byte("line-rate=")) {
		return KindCobertura
	}
	return KindUnknown
}

func looksLCOV(content []byte) bool {
	scanned := content
	if len(scanned) > 32*1024 {
		scanned = scanned[:32*1024]
	}
	hasSF := false
	hasRecord := false
	for _, line := range bytes.Split(scanned, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("SF:")) {
			hasSF = true
		}
		if bytes.Equal(line, []byte("end_of_record")) || bytes.HasPrefix(line, []byte("DA:")) || bytes.HasPrefix(line, []byte("LF:")) {
			hasRecord = true
		}
		if hasSF && hasRecord {
			return true
		}
	}
	return false
}

func isJSONArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '['
}

func jsonArrayEmpty(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("[]"))
}
