package format

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/olekukonko/ll"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

// TableJSON is the JSON form of a table. Each row is an object keyed by the
// column header.
type TableJSON struct {
	Columns []string            `json:"columns"`
	Rows    []map[string]string `json:"rows"`
	Footer  map[string]string   `json:"footer,omitempty"`
}

// NewJSONTable returns a table that writes TableJSON instead of drawing a grid.
// Cells are not wrapped or padded.
func NewJSONTable(w io.Writer) *tablewriter.Table {
	return tablewriter.NewTable(w,
		tablewriter.WithRenderer(&jsonRenderer{}),
		tablewriter.WithRowAutoWrap(tw.WrapNone),
		tablewriter.WithHeaderAutoFormat(tw.Off),
		tablewriter.WithFooterAutoFormat(tw.Off),
		tablewriter.WithPadding(tw.Padding{Overwrite: true}),
	)
}

// WriteEmptyJSON writes a TableJSON with no rows and a message.
func WriteEmptyJSON(w io.Writer, message string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Columns []string            `json:"columns"`
		Rows    []map[string]string `json:"rows"`
		Message string              `json:"message"`
	}{Columns: []string{}, Rows: []map[string]string{}, Message: message})
}

type jsonRenderer struct {
	w   io.Writer
	out TableJSON
}

func (r *jsonRenderer) Start(w io.Writer) error {
	r.w = w
	r.out = TableJSON{Columns: []string{}, Rows: []map[string]string{}}
	return nil
}

func (r *jsonRenderer) Header(headers [][]string, _ tw.Formatting) {
	if len(headers) > 0 {
		r.out.Columns = append([]string(nil), headers[0]...)
	}
}

func (r *jsonRenderer) Row(row []string, _ tw.Formatting) {
	r.out.Rows = append(r.out.Rows, r.keyed(row))
}

func (r *jsonRenderer) Footer(footers [][]string, _ tw.Formatting) {
	if len(footers) > 0 {
		r.out.Footer = r.keyed(footers[0])
	}
}

func (r *jsonRenderer) keyed(cells []string) map[string]string {
	m := make(map[string]string, len(cells))
	for i, cell := range cells {
		key := ""
		if i < len(r.out.Columns) {
			key = r.out.Columns[i]
		}
		if key == "" {
			key = fmt.Sprintf("column%d", i+1)
		}
		m[key] = cell
	}
	return m
}

func (r *jsonRenderer) Line(tw.Formatting)   {}
func (r *jsonRenderer) Config() tw.Rendition { return tw.Rendition{} }
func (r *jsonRenderer) Logger(*ll.Logger)    {}
func (r *jsonRenderer) Close() error {
	enc := json.NewEncoder(r.w)
	enc.SetIndent("", "  ")
	return enc.Encode(r.out)
}
