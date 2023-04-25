package strings

import (
	"fmt"
	"strings"
)

type Table struct {
	headerItems []string
	rows        [][]string
	footer      string

	sortBy     []SortBy
	numColumns int
}

func NewTable(header ...string) *Table {
	return &Table{
		headerItems: header,
		numColumns:  len(header),
	}
}

func (t Table) WithHeader(items ...string) *Table {
	t.headerItems = items
	t.numColumns = len(items)
	return &t
}

func (t Table) WithRow(row ...string) *Table {
	t.rows = append(t.rows, row)
	return &t
}

func (t Table) WithFooter(item string) *Table {
	t.footer = item
	return &t
}

func (t *Table) NumRows() int {
	return len(t.rows)
}

func (t *Table) TotalsByCol(col int) map[string]int {
	m := map[string]int{}
	for _, row := range t.rows {
		m[row[col]] += 1
	}
	return m
}

// SortBy sets the rules for sorting the Rows in the order specified. i.e., the
// first SortBy instruction takes precedence over the second and so on. Any
// duplicate instructions on the same column will be discarded while sorting.
func (t Table) SortBy(sortBy []SortBy) *Table {
	t.sortBy = sortBy
	return &t
}

func (t Table) Sort() *Table {
	if len(t.sortBy) == 0 {
		return &t
	}

	// sort the rows
	sortedRowIndices := t.getSortedRowIndices()
	sortedRows := make([][]string, len(t.rows))
	for idx := range t.rows {
		sortedRows[idx] = t.rows[sortedRowIndices[idx]]
	}
	t.rows = sortedRows

	return &t
}

func (t Table) String() string {
	var sb strings.Builder
	colLens := t.columnLengths()
	data := append([][]string{t.headerItems}, t.rows...)

	sb.WriteString(t.divider() + "\n")
	for rowIndex, row := range data {
		rowStrings := make([]string, len(t.headerItems))

		rowLength := MinInt(len(t.headerItems), len(row))
		for i := 0; i < rowLength; i++ {
			s := fmt.Sprintf("%%-%ds", colLens[i])
			s = fmt.Sprintf(s, row[i])
			rowStrings[i] = s
		}
		sb.WriteString(strings.Join(rowStrings, " | ") + "\n")
		if rowIndex == 0 {
			sb.WriteString(t.divider() + "\n")
		}
	}

	if t.footer != "" {
		sb.WriteString(t.divider() + "\n")
		sb.WriteString(t.footer + "\n")
		sb.WriteString(t.divider() + "\n")
	}

	return sb.String()
}

// Single line map string format from "map[foo:90 bar:30]" to "(foo: 90, bar: 30)"
func PrettyPrintMap[K comparable, V any](m map[K]V) string {
	s := ""
	for k, v := range m {
		s += fmt.Sprintf("%v: %v, ", k, v)
	}
	if s != "" {
		return fmt.Sprintf("(%s)", s[:len(s)-2])
	}
	return s
}

// Private helper functions

// columnLengths finds the longest string in each column
func (t Table) columnLengths() []int {
	rowLengths := make([]int, len(t.headerItems))

	dataRows := append([][]string{t.headerItems}, t.rows...)

	for _, row := range dataRows {
		for i := 0; i < MinInt(len(row), len(t.headerItems)); i++ {
			rowLengths[i] = MaxInt(rowLengths[i], len(row[i]))
		}
	}

	return rowLengths
}

func (t Table) divider() string {
	sum := 0
	for _, v := range t.columnLengths() {
		sum = sum + v
	}
	// Add extra '-' since the item dividers add length
	return strings.Repeat("-", sum) + strings.Repeat("-", len(t.columnLengths())*3-1)
}

func CleanAndAbbreviate(s string, maxLength int) string {
	if len(s) > maxLength {
		s = s[:maxLength-3] + "..."
	}
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

func MaxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
func MinInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
