package strings

import (
	"sort"
	"strconv"
)

type SortBy struct {
	Name   string
	Number int
	Mode   SortMode
	Order  StrOrder
}

// StrOrder defines a custom index to sort by. 	Ex: StrOrder{"Hot", "Warm", "Cold"}
type StrOrder []string

// SortMode defines How to sort.
type SortMode int

const (
	// Asc sorts the column in Ascending order alphabetically.
	Asc SortMode = iota
	// AscNumeric sorts the column in Ascending order numerically.
	AscNumeric
	// Custom sorts the column in Ascending order by custom string index order
	AscCustom
	// Dsc sorts the column in Descending order alphabetically.
	Dsc
	// DscNumeric sorts the column in Descending order numerically.
	DscNumeric
	// Custom sorts the column in Descending order by custom string index order
	DscCustom
)

type rowsSorter struct {
	rows          [][]string
	sortBy        []SortBy
	sortedIndices []int
}

// getSortedRowIndices sorts and returns the row indices in Sorted order as
// directed by Table.sortBy which can be set using Table.SortBy(...)
func (t *Table) getSortedRowIndices() []int {
	sortedIndices := make([]int, len(t.rows))
	for idx := range t.rows {
		sortedIndices[idx] = idx
	}

	if t.sortBy != nil && len(t.sortBy) > 0 {
		sort.Sort(rowsSorter{
			rows:          t.rows,
			sortBy:        t.parseSortBy(t.sortBy),
			sortedIndices: sortedIndices,
		})
	}

	return sortedIndices
}

func (t *Table) parseSortBy(sortBy []SortBy) []SortBy {
	var resSortBy []SortBy
	for _, col := range sortBy {
		colNum := 0
		if col.Number > 0 && col.Number <= t.numColumns {
			colNum = col.Number
		} else if col.Name != "" && len(t.headerItems) > 0 {
			for idx, colName := range t.headerItems {
				if col.Name == colName {
					colNum = idx + 1
					break
				}
			}
		}
		if colNum > 0 {
			resSortBy = append(resSortBy, SortBy{
				Name:   col.Name,
				Number: colNum,
				Mode:   col.Mode,
				Order:  col.Order,
			})
		}
	}
	return resSortBy
}

func (rs rowsSorter) Len() int {
	return len(rs.rows)
}

func (rs rowsSorter) Swap(i, j int) {
	rs.sortedIndices[i], rs.sortedIndices[j] = rs.sortedIndices[j], rs.sortedIndices[i]
}

func (rs rowsSorter) Less(i, j int) bool {
	realI, realJ := rs.sortedIndices[i], rs.sortedIndices[j]
	for _, col := range rs.sortBy {
		rowI, rowJ, colIdx := rs.rows[realI], rs.rows[realJ], col.Number-1
		if colIdx < len(rowI) && colIdx < len(rowJ) {
			shouldContinue, returnValue := rs.lessColumns(rowI, rowJ, colIdx, col)
			if !shouldContinue {
				return returnValue
			}
		}
	}
	return false
}

func (rs rowsSorter) lessColumns(rowI []string, rowJ []string, colIdx int, col SortBy) (bool, bool) {
	if rowI[colIdx] == rowJ[colIdx] {
		return true, false
	} else if col.Mode == Asc {
		return false, rowI[colIdx] < rowJ[colIdx]
	} else if col.Mode == Dsc {
		return false, rowI[colIdx] > rowJ[colIdx]
	} else if col.Mode == AscCustom {
		return false, col.Order.index(rowI[colIdx]) < col.Order.index(rowJ[colIdx])
	} else if col.Mode == DscCustom {
		return false, col.Order.index(rowI[colIdx]) > col.Order.index(rowJ[colIdx])
	}

	// Sort Numerically
	iVal, iErr := strconv.ParseFloat(rowI[colIdx], 64)
	jVal, jErr := strconv.ParseFloat(rowJ[colIdx], 64)
	if iErr == nil && jErr == nil {
		if col.Mode == AscNumeric {
			return false, iVal < jVal
		} else if col.Mode == DscNumeric {
			return false, jVal < iVal
		}
	}
	return true, false
}

// Finds the index of a string in an array
func (strOrder StrOrder) index(s string) int {
	for i, str := range strOrder {
		if str == s {
			return i
		}
	}
	return 0
}
