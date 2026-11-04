// Package vex reads OpenVEX and CycloneDX VEX documents and decides which
// scanner findings they mark as not exploitable.
package vex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

// Format is the kind of VEX document.
type Format string

const (
	FormatOpenVEX   Format = "openvex"
	FormatCycloneDX Format = "cyclonedx"
)

// ErrUnknownFormat means the document is neither OpenVEX nor CycloneDX VEX.
var ErrUnknownFormat = errors.New("not an OpenVEX or CycloneDX VEX document")

// Statement is one VEX claim about one vulnerability.
type Statement struct {
	// IDs are the vulnerability id and its aliases.
	IDs []string
	// Packages are package URLs the statement is limited to. Empty means the
	// statement applies to every package with a matching id.
	Packages []string
	// Status is the status word from the document, such as not_affected or
	// false_positive.
	Status string
	// Justification is the OpenVEX justification or CycloneDX analysis
	// justification, when there is one.
	Justification string
	// Suppress is true when Status means the finding is not exploitable.
	Suppress bool
	// Source is the file the statement came from.
	Source    string
	Timestamp time.Time
}

// Document is the merged set of statements from one or more VEX files.
type Document struct {
	Statements []Statement
}

// Finding is the part of a scanner finding VEX matching needs.
type Finding struct {
	IDs  []string
	PURL string
}

// Load reads and merges VEX files.
func Load(filenames ...string) (*Document, error) {
	doc := &Document{}
	for _, name := range filenames {
		if strings.TrimSpace(name) == "" {
			continue
		}
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		part, err := Decode(f, name)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("vex %s: %w", name, err)
		}
		doc.Merge(part)
	}
	return doc, nil
}

// Decode reads one OpenVEX or CycloneDX VEX document. source names it in logs.
func Decode(r io.Reader, source string) (*Document, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var probe struct {
		Context    string          `json:"@context"`
		BOMFormat  string          `json:"bomFormat"`
		Statements json.RawMessage `json:"statements"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, err
	}
	switch {
	case strings.Contains(strings.ToLower(probe.Context), "openvex") || len(probe.Statements) > 0:
		return decodeOpenVEX(body, source)
	case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
		return decodeCycloneDX(body, source)
	default:
		return nil, ErrUnknownFormat
	}
}

// Merge appends other's statements. Later files win ties on timestamp.
func (d *Document) Merge(other *Document) {
	if other == nil {
		return
	}
	d.Statements = append(d.Statements, other.Statements...)
}

// Len is the number of statements.
func (d *Document) Len() int {
	if d == nil {
		return 0
	}
	return len(d.Statements)
}

// Match returns the statement that decides f, and whether there is one.
// When several statements match, the one with the latest timestamp wins, and
// the later one in file order breaks ties. A later "affected" statement
// therefore overrides an earlier "not_affected".
func (d *Document) Match(f Finding) (Statement, bool) {
	if d == nil {
		return Statement{}, false
	}
	var best Statement
	found := false
	for _, s := range d.Statements {
		if !s.matches(f) {
			continue
		}
		if !found || !s.Timestamp.Before(best.Timestamp) {
			best = s
			found = true
		}
	}
	return best, found
}

// Suppressed reports whether the deciding statement for f marks it not exploitable.
func (d *Document) Suppressed(f Finding) (Statement, bool) {
	s, ok := d.Match(f)
	if !ok || !s.Suppress {
		return Statement{}, false
	}
	return s, true
}

func (s Statement) matches(f Finding) bool {
	idMatch := false
	for _, want := range s.IDs {
		for _, got := range f.IDs {
			if want != "" && strings.EqualFold(want, got) {
				idMatch = true
			}
		}
	}
	if !idMatch {
		return false
	}
	if len(s.Packages) == 0 || strings.TrimSpace(f.PURL) == "" {
		return true
	}
	for _, p := range s.Packages {
		if PURLMatches(p, f.PURL) {
			return true
		}
	}
	return false
}

// PURLMatches compares package URLs by type, namespace, and name. The version
// must also match when want has one. Qualifiers and subpaths are ignored.
func PURLMatches(want, got string) bool {
	wb, wv, ok := splitPURL(want)
	if !ok {
		return false
	}
	gb, gv, ok := splitPURL(got)
	if !ok {
		return false
	}
	if wb != gb {
		return false
	}
	return wv == "" || wv == gv
}

func splitPURL(p string) (base, version string, ok bool) {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(strings.ToLower(p), "pkg:") {
		return "", "", false
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, "@"); i > strings.LastIndex(p, "/") {
		version = p[i+1:]
		p = p[:i]
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	if b, err := url.PathUnescape(p); err == nil {
		p = b
	}
	parts := strings.SplitN(p[len("pkg:"):], "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", false
	}
	return strings.ToLower(parts[0]) + "/" + parts[1], version, true
}

// OpenVEX

type openVEXDoc struct {
	Timestamp   string             `json:"timestamp"`
	LastUpdated string             `json:"last_updated"`
	Statements  []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability json.RawMessage   `json:"vulnerability"`
	Products      []json.RawMessage `json:"products"`
	Subcomponents []json.RawMessage `json:"subcomponents"`
	Status        string            `json:"status"`
	Justification string            `json:"justification"`
	Timestamp     string            `json:"timestamp"`
	LastUpdated   string            `json:"last_updated"`
}

type openVEXVulnerability struct {
	ID      string   `json:"@id"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
}

type openVEXComponent struct {
	ID            string            `json:"@id"`
	Identifiers   map[string]string `json:"identifiers"`
	Subcomponents []json.RawMessage `json:"subcomponents"`
}

func decodeOpenVEX(body []byte, source string) (*Document, error) {
	var raw openVEXDoc
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	docTime := firstTime(raw.LastUpdated, raw.Timestamp)
	doc := &Document{}
	for _, st := range raw.Statements {
		ids, err := openVEXIDs(st.Vulnerability)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			continue
		}
		var pkgs []string
		for _, sub := range st.Subcomponents {
			pkgs = append(pkgs, componentPURLs(sub)...)
		}
		for _, product := range st.Products {
			pkgs = append(pkgs, productSubcomponentPURLs(product)...)
		}
		ts := firstTime(st.LastUpdated, st.Timestamp)
		if ts.IsZero() {
			ts = docTime
		}
		status := strings.ToLower(strings.TrimSpace(st.Status))
		doc.Statements = append(doc.Statements, Statement{
			IDs:           ids,
			Packages:      pkgs,
			Status:        status,
			Justification: st.Justification,
			Suppress:      status == "not_affected" || status == "fixed",
			Source:        source,
			Timestamp:     ts,
		})
	}
	return doc, nil
}

func openVEXIDs(raw json.RawMessage) ([]string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		return appendID(nil, name), nil
	}
	var v openVEXVulnerability
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("statement vulnerability: %w", err)
	}
	ids := appendID(nil, v.Name)
	ids = appendID(ids, v.ID)
	for _, alias := range v.Aliases {
		ids = appendID(ids, alias)
	}
	return ids, nil
}

// componentPURLs returns the package URLs that identify one component entry,
// which is either a string or an object with @id and identifiers.purl.
func componentPURLs(raw json.RawMessage) []string {
	var id string
	if err := json.Unmarshal(raw, &id); err == nil {
		return purlOnly(id)
	}
	var c openVEXComponent
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil
	}
	out := purlOnly(c.ID)
	out = append(out, purlOnly(c.Identifiers["purl"])...)
	return out
}

// productSubcomponentPURLs returns the package URLs of a product's
// subcomponents. The product itself is what was scanned, such as an image, so
// it does not narrow which findings match.
func productSubcomponentPURLs(raw json.RawMessage) []string {
	var c openVEXComponent
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil
	}
	var out []string
	for _, sub := range c.Subcomponents {
		out = append(out, componentPURLs(sub)...)
	}
	return out
}

// CycloneDX

type cdxDoc struct {
	Metadata struct {
		Timestamp string `json:"timestamp"`
	} `json:"metadata"`
	Components      []cdxComponent `json:"components"`
	Vulnerabilities []struct {
		ID         string `json:"id"`
		References []struct {
			ID string `json:"id"`
		} `json:"references"`
		Analysis *struct {
			State         string `json:"state"`
			Justification string `json:"justification"`
			LastUpdated   string `json:"lastUpdated"`
			FirstIssued   string `json:"firstIssued"`
		} `json:"analysis"`
		Affects []struct {
			Ref string `json:"ref"`
		} `json:"affects"`
		Updated   string `json:"updated"`
		Published string `json:"published"`
	} `json:"vulnerabilities"`
}

type cdxComponent struct {
	BOMRef     string         `json:"bom-ref"`
	PURL       string         `json:"purl"`
	Components []cdxComponent `json:"components"`
}

func decodeCycloneDX(body []byte, source string) (*Document, error) {
	var raw cdxDoc
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	refs := map[string]string{}
	var walk func([]cdxComponent)
	walk = func(components []cdxComponent) {
		for _, c := range components {
			if c.BOMRef != "" && c.PURL != "" {
				refs[c.BOMRef] = c.PURL
			}
			walk(c.Components)
		}
	}
	walk(raw.Components)

	docTime := firstTime(raw.Metadata.Timestamp)
	doc := &Document{}
	for _, v := range raw.Vulnerabilities {
		if v.Analysis == nil || strings.TrimSpace(v.Analysis.State) == "" {
			continue
		}
		ids := appendID(nil, v.ID)
		for _, ref := range v.References {
			ids = appendID(ids, ref.ID)
		}
		if len(ids) == 0 {
			continue
		}
		var pkgs []string
		for _, a := range v.Affects {
			if p, ok := refs[a.Ref]; ok {
				pkgs = append(pkgs, p)
				continue
			}
			pkgs = append(pkgs, purlOnly(a.Ref)...)
		}
		ts := firstTime(v.Analysis.LastUpdated, v.Updated, v.Analysis.FirstIssued, v.Published)
		if ts.IsZero() {
			ts = docTime
		}
		state := strings.ToLower(strings.TrimSpace(v.Analysis.State))
		doc.Statements = append(doc.Statements, Statement{
			IDs:           ids,
			Packages:      pkgs,
			Status:        state,
			Justification: v.Analysis.Justification,
			Suppress:      cdxSuppresses(state),
			Source:        source,
			Timestamp:     ts,
		})
	}
	return doc, nil
}

func cdxSuppresses(state string) bool {
	switch state {
	case "not_affected", "false_positive", "resolved", "resolved_with_pedigree":
		return true
	default:
		return false
	}
}

func purlOnly(id string) []string {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(strings.ToLower(id), "pkg:") {
		return []string{id}
	}
	return nil
}

func appendID(ids []string, id string) []string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ids
	}
	for _, got := range ids {
		if strings.EqualFold(got, id) {
			return ids
		}
	}
	return append(ids, id)
}

func firstTime(values ...string) time.Time {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t
		}
		if t, err := time.Parse("2006-01-02", v); err == nil {
			return t
		}
	}
	return time.Time{}
}
