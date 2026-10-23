package format

import (
	"io"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

// NewTable returns an ASCII table in the style the CLI used with tablewriter v0:
// '+' corners, '-' rules, '|' columns, centered headers, and a 30-column wrap.
// Header auto-format stays on so labels are uppercased the way v0's Title did.
// Footer auto-format stays off; v1's formatter also splits values like "50.00%".
func NewTable(w io.Writer) *tablewriter.Table {
	return tablewriter.NewTable(w,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Symbols: tw.NewSymbols(tw.StyleASCII),
		})),
		// 32 includes the single-space padding on each side, so cell text wraps at 30.
		tablewriter.WithRowMaxWidth(32),
		tablewriter.WithHeaderAutoFormat(tw.On),
		tablewriter.WithFooterAlignmentConfig(tw.CellAlignment{Global: tw.AlignCenter}),
	)
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

// SetBorderless removes the outer border, matching tablewriter v0 SetBorder(false).
func SetBorderless(table *tablewriter.Table) {
	table.Options(tablewriter.WithRendition(tw.Rendition{
		Borders: tw.Border{Left: tw.Off, Right: tw.Off, Top: tw.Off, Bottom: tw.Off},
	}))
}
