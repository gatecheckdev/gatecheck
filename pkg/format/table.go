package format

import (
	"bytes"
	"fmt"
	"strings"
)

type Table struct {
	data           [][]string
	selectedColumn int
	lessFunc       func(a, b string) bool
}

func NewTable() *Table {
	return &Table{data: make([][]string, 0), selectedColumn: 0, lessFunc: AlphabeticLess}
}

func (t *Table) AppendRow(values ...string) {
	t.data = append(t.data, values)
}

func (t *Table) Select(columnIndex uint) {
	if columnIndex > uint(len(t.data[0])-1) {
		columnIndex = uint(len(t.data[0]) - 1)
	}

	t.selectedColumn = int(columnIndex)
}

func (t *Table) SetSort(columnIndex uint, lessFunc func(a, b string) bool) {
	t.Select(columnIndex)
	t.lessFunc = lessFunc
}

func (t *Table) Body() [][]string {
	return t.data[1:]
}

func (t *Table) Len() int {
	return len(t.Body())
}

func (t *Table) Swap(i, j int) {
	t.Body()[i], t.Body()[j] = t.Body()[j], t.Body()[i]
}

func (t *Table) Less(i, j int) bool {
	return t.lessFunc(t.Body()[i][t.selectedColumn], t.Body()[j][t.selectedColumn])
}

func (t *Table) maxLenByColumn() []int {
	colMaxLengths := make([]int, 0)
	for _, row := range t.data {
		for i, item := range row {
			if len(colMaxLengths) < i+1 {
				colMaxLengths = append(colMaxLengths, 0)
			}
			if colMaxLengths[i] < len(item) {
				colMaxLengths[i] = len(item)
			}
		}
	}
	return colMaxLengths
}

func AlphabeticLess(a, b string) bool {
	return a < b
}

func NewCatagoricLess(categories []string) func(a, b string) bool {
	return func(a, b string) bool {
		aIndex, bIndex := 0, 0
		for i, category := range categories {
			if a == category {
				aIndex = i
			}
			if b == category {
				bIndex = i
			}
		}
		return aIndex < bIndex
	}
}

type TableCharacter int

const (
	HLINE TableCharacter = iota
	VLINE
	MIDLLINE
	MIDRLINE
	TLCORNER
	TRCORNER
	BLCORNER
	BRCORNER
)

var PrettyCharMap = map[TableCharacter]string{
	HLINE:    "\u2500",
	VLINE:    "\u2502",
	MIDLLINE: "\u251C",
	MIDRLINE: "\u2524",
	TLCORNER: "\u250C",
	TRCORNER: "\u2510",
	BLCORNER: "\u2514",
	BRCORNER: "\u2518",
}

var PrettyCharMapRoundedCorners = map[TableCharacter]string{
	HLINE:    PrettyCharMap[HLINE],
	VLINE:    PrettyCharMap[VLINE],
	MIDLLINE: PrettyCharMap[MIDLLINE],
	MIDRLINE: PrettyCharMap[MIDRLINE],
	TLCORNER: "\u256D",
	TRCORNER: "\u256E",
	BLCORNER: "\u2570",
	BRCORNER: "\u256F",
}

var ASCIICharMap = map[TableCharacter]string{
	HLINE:    "-",
	VLINE:    "|",
	MIDLLINE: "|",
	MIDRLINE: "|",
	TLCORNER: " ",
	TRCORNER: " ",
	BLCORNER: " ",
	BRCORNER: " ",
}

type TableWriter struct {
	bytes.Buffer
	chars map[TableCharacter]string
}

func NewTableWriter(t *Table) *TableWriter {
	tw := &TableWriter{
		chars: PrettyCharMap,
	}
	return tw.WithTable(t)
}

func (w *TableWriter) WithCharMap(m map[TableCharacter]string) *TableWriter {
	w.chars = m
	return w
}

func (w *TableWriter) WithTable(t *Table) *TableWriter {
	w.Reset()
	var sb strings.Builder
	var rowLength int

	colMaxLengths := t.maxLenByColumn()
	for i, row := range t.data {
		if i == 1 {
			sb.WriteString(w.chars[MIDLLINE] + strings.Repeat(w.chars[HLINE], rowLength-1) + w.chars[MIDRLINE] + "\n")
		}
		rowLength = 0
		sb.WriteString(w.chars[VLINE])
		for i, item := range row {
			padding := colMaxLengths[i]
			formatString := fmt.Sprintf(" %%-%ds ", padding) //+ VLINE
			line := fmt.Sprintf(formatString, item)
			rowLength = rowLength + len(line) + 1
			sb.WriteString(line + w.chars[VLINE])
		}
		sb.WriteString("\n")
	}

	w.WriteString(w.chars[TLCORNER] + strings.Repeat(w.chars[HLINE], rowLength-1) + w.chars[TRCORNER] + "\n")
	w.WriteString(sb.String())
	w.WriteString(w.chars[BLCORNER] + strings.Repeat(w.chars[HLINE], rowLength-1) + w.chars[BRCORNER] + "\n")

	return w
}
