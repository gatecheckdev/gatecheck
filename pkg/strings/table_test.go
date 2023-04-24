package strings

import (
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
