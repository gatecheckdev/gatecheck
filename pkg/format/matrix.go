package format

import (
	"github.com/olekukonko/tablewriter"
)

type SortableMatrix struct {
	data           [][]string
	selectedColumn int
	lessFunc       func(a, b string) bool
}

func NewSortableMatrix(data [][]string, sortColIdx int, sortFunc func(a, b string) bool) *SortableMatrix {
	return &SortableMatrix{
		data:           data,
		selectedColumn: sortColIdx,
		lessFunc:       sortFunc,
	}
}

func (m *SortableMatrix) Append(row []string) {
	m.data = append(m.data, row)
}

func (m *SortableMatrix) Matrix() [][]string {
	return m.data
}

func (m *SortableMatrix) Table(table *tablewriter.Table) {
	table.AppendBulk(m.data)
}

func (m *SortableMatrix) Len() int {
	return len(m.data)
}

func (m *SortableMatrix) Swap(i, j int) {
	m.data[i], m.data[j] = m.data[j], m.data[i]
}

func (m *SortableMatrix) Less(i, j int) bool {
	return m.lessFunc(m.data[i][m.selectedColumn], m.data[j][m.selectedColumn])
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
