package strings

import (
	"testing"
)

func TestSortTable_SingleCol(t *testing.T) {
	table := NewTable("ColumnName")
	table = table.WithRow("C")
	table = table.WithRow("B")
	table = table.WithRow("A")

	expected := [][]string{{"C"}, {"B"}, {"A"}}

	for idx, str := range table.rows {
		if expected[idx][0] != str[0] {
			t.Fatal("Expected", expected[idx][0], "got", str[0])
		}
	}

	expected = [][]string{{"A"}, {"B"}, {"C"}}

	table = table.SortBy([]SortBy{
		{Name: "ColumnName", Mode: Asc},
	}).Sort()

	for idx, str := range table.rows {
		if expected[idx][0] != str[0] {
			t.Fatal("Expected", expected[idx][0], "got", str[0])
		}
	}

	expected = [][]string{{"C"}, {"B"}, {"A"}}

	table = table.SortBy([]SortBy{
		{Name: "ColumnName", Mode: Dsc},
	}).Sort()

	for idx, str := range table.rows {
		if expected[idx][0] != str[0] {
			t.Fatal("Expected", expected[idx][0], "got", str[0])
		}
	}

}

func TestSortTable_CustomSort(t *testing.T) {
	table := NewTable("ColumnName")
	table = table.WithRow("Cold")
	table = table.WithRow("Hot")
	table = table.WithRow("Warm")
	table = table.WithRow("Hot")

	expected := [][]string{
		{"Cold"},
		{"Hot"},
		{"Warm"},
		{"Hot"},
	}

	for idx, str := range table.rows {
		if expected[idx][0] != str[0] {
			t.Fatal("Expected", expected[idx][0], "got", str[0])
		}
	}

	expected = [][]string{
		{"Hot"},
		{"Hot"},
		{"Warm"},
		{"Cold"},
	}

	table = table.SortBy([]SortBy{
		{Name: "ColumnName", Mode: AscCustom, Order: StrOrder{"Hot", "Warm", "Cold"}},
	}).Sort()

	for idx, str := range table.rows {
		if expected[idx][0] != str[0] {
			t.Fatal("Expected", expected[idx][0], "got", str[0])
		}
	}
}

func TestSortTable_MultiCol(t *testing.T) {
	table := NewTable("ColumnName", "Value")
	table = table.WithRow("B", "2")
	table = table.WithRow("B", "1")
	table = table.WithRow("A", "1")
	table = table.WithRow("A", "2")

	expected := [][]string{
		{"B", "2"},
		{"B", "1"},
		{"A", "1"},
		{"A", "2"},
	}

	for i, row := range table.rows {
		for j := range row {
			if expected[i][j] != table.rows[i][j] {
				t.Fatal("Expected", expected[i][j], "got", table.rows[i][j])
			}
		}
	}

	expected = [][]string{
		{"A", "1"},
		{"A", "2"},
		{"B", "1"},
		{"B", "2"},
	}

	table = table.SortBy([]SortBy{
		{Name: "ColumnName", Mode: Asc},
		{Name: "Value", Mode: Asc},
	}).Sort()

	for i, row := range table.rows {
		for j := range row {
			if expected[i][j] != table.rows[i][j] {
				t.Fatal("Expected", expected[i][j], "got", table.rows[i][j])
			}
		}
	}

	expected = [][]string{
		{"B", "1"},
		{"B", "2"},
		{"A", "1"},
		{"A", "2"},
	}

	table = table.SortBy([]SortBy{
		{Name: "ColumnName", Mode: Dsc},
		{Name: "Value", Mode: Asc},
	}).Sort()

	for i, row := range table.rows {
		for j := range row {
			if expected[i][j] != table.rows[i][j] {
				t.Fatal("Expected", expected[i][j], "got", table.rows[i][j])
			}
		}
	}
}
