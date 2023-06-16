package format

import (
	"sort"
	"testing"
)

func TestTable_AppendRow(t *testing.T) {
	table := NewTable()
	table.AppendRow("column 1", "column 2", "column 3")
	table.AppendRow("value 1", "value 2", "B")
	table.AppendRow("value 4", "value 5", "C")
	table.AppendRow("value 4", "value 5", "A")
	table.AppendRow("value 4", "value 5", "G")

	table.Select(10)
	t.Log(table.selectedColumn)
	sort.Sort(table)

	t.Log("\n" + NewTableWriter(table).WithCharMap(PrettyCharMapRoundedCorners).String())
}

func TestCatagoricLess(t *testing.T) {
	table := NewTable()

	table.AppendRow("Severity", "Package", "Version", "Link")
	table.AppendRow("Critical", "pkg1", "v1", "somelink")
	table.AppendRow("Negligible", "pkg1", "v1", "somelink")
	table.AppendRow("Low", "pkg1", "v1", "somelink")
	table.AppendRow("High", "pkg1", "v1", "somelink")
	table.AppendRow("Critical", "pkg1", "v1", "somelink")

	table.SetSort(0, NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}))
	t.Log("\n" + NewTableWriter(table).String())
	sort.Sort(table)
	t.Log("\n" + NewTableWriter(table).String())
}
