package strings

import (
	"fmt"
	"strings"
	"testing"
)

func TestTable_WithHeader(t *testing.T) {
	table := NewTable("One", "Two", "Three", "Four", "Five")
	table = table.WithRow("A", "B", "C", "len of 8")
	table = table.WithRow("Some longer A", "Text in the B", "Rows than the header C", "D")

	numColumns := table.numColumns
	expectedColumns := 5
	if numColumns != expectedColumns {
		t.Fatal("Number of columns expected", expectedColumns, "got", numColumns)
	}

	colLengths := table.columnLengths()
	expectedLengths := []int{13, 13, 22, 8, 4}
	for i := range table.columnLengths() {
		if colLengths[i] != expectedLengths[i] {
			t.Fatal(table.columnLengths())
		}
	}

	t.Log("\n" + table.String())

	if strings.Contains(table.String(), "Some longer A") == false {
		t.Fatal(table.String())
	}

	table = table.WithHeader("1", "2", "3", "4", "5")

	t.Log("\n" + table.String())
}

func TestCleanAndAbbreviate(t *testing.T) {
	input := "One fish Two Fish Red Fish Blue Fish"
	expected := "One fish ..."
	output := CleanAndAbbreviate(input, 12)
	if output != expected {
		t.Fatal("For", input, "expected", expected, "got", output)
	}
}

func TestFooterAndTotals(t *testing.T) {
	table := NewTable("ColumnName")
	table = table.WithRow("Hot")
	table = table.WithRow("Hot")
	table = table.WithRow("Hot")
	table = table.WithRow("Warm")
	table = table.WithRow("Warm")
	table = table.WithRow("Cold")
	table = table.SortBy([]SortBy{
		{Name: "ColumnName", Mode: AscCustom, Order: StrOrder{"Hot", "Warm", "Cold"}},
	}).Sort()

	expectedTotal := 6
	expected := map[string]int{
		"Hot":  3,
		"Warm": 2,
		"Cold": 1,
	}
	t.Parallel()

	t.Run("table-col-totals", func(t *testing.T) {

		totals := table.TotalsByCol(0)
		for k, v := range expected {
			if ev, ok := totals[k]; ok {
				if ev != v {
					t.Fatal("Expected", v, "got", ev)
				}
			} else {
				t.Fatal("Expected key for", k, "got", nil)
			}
		}
	})

	t.Run("table-row-count", func(t *testing.T) {
		total := table.NumRows()
		if total != expectedTotal {
			t.Fatal("Expected", expectedTotal, "got", total)
		}
	})

	t.Run("table-footer", func(t *testing.T) {
		total := table.NumRows()
		expectedFooter := fmt.Sprintf("Total %d", total)
		tableStr := table.WithFooter(expectedFooter).String()
		if !strings.Contains(tableStr, expectedFooter) {
			t.Fatal("Expected '", expectedFooter, "' in table but got", tableStr)
		}
	})

	t.Run("pretty-print-map", func(t *testing.T) {
		m := map[string]int{
			"Hot": 2,
		}
		expectedStr := "(Hot: 2)"
		str := PrettyPrintMap(m)
		if str != expectedStr {
			t.Fatal("Expected", expectedStr, "got", str)
		}
	})
}
