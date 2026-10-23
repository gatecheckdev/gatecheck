package format

import (
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

// NewTable returns an ASCII table in the style the CLI used with tablewriter v0:
// '+' corners, '-' rules, '|' columns, centered headers, and a 30-column wrap.
// v1 header and footer auto-format is off. That formatter splits words such as
// "IDs" and values such as "50.00%". Headers and footers are uppercased here.
func NewTable(w io.Writer) *tablewriter.Table {
	upper := tw.CellFilter{Global: upperCells}
	return tablewriter.NewTable(w,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Symbols: tw.NewSymbols(tw.StyleASCII),
		})),
		// 32 includes the single-space padding on each side, so cell text wraps at 30.
		tablewriter.WithRowMaxWidth(32),
		tablewriter.WithHeaderAutoFormat(tw.Off),
		tablewriter.WithFooterAutoFormat(tw.Off),
		tablewriter.WithHeaderFilter(upper),
		tablewriter.WithFooterFilter(upper),
		tablewriter.WithFooterAlignmentConfig(tw.CellAlignment{Global: tw.AlignCenter}),
	)
}

func upperCells(cells []string) []string {
	out := make([]string, len(cells))
	for i, cell := range cells {
		out[i] = strings.ToUpper(cell)
	}
	return out
}

// SetMarkdown applies the legacy markdown layout: left and right borders only,
// '|' as the center separator, and no row wrapping.
func SetMarkdown(table *tablewriter.Table) {
	table.Options(
		tablewriter.WithRendition(tw.Rendition{
			Borders: tw.Border{Left: tw.On, Top: tw.Off, Right: tw.On, Bottom: tw.Off},
			Symbols: tw.NewSymbolCustom("markdown").
				WithCenter("|").
				WithRow("-").
				WithColumn("|").
				WithTopLeft("+").
				WithTopMid("+").
				WithTopRight("+").
				WithMidLeft("|").
				WithMidRight("|").
				WithBottomLeft("+").
				WithBottomMid("+").
				WithBottomRight("+").
				WithHeaderLeft("|").
				WithHeaderMid("|").
				WithHeaderRight("|"),
		}),
		tablewriter.WithRowAutoWrap(tw.WrapNone),
	)
}
