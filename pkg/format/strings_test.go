package format

import (
	"testing"
)

func TestSummarize(t *testing.T) {
	testTable := []struct {
		content string
		length  int
		clip    ClipDirection
		want    string
	}{
		{content: "abcdefg", length: 5, clip: ClipRight, want: "ab..."},
		{content: "abcdefg", length: 5, clip: ClipLeft, want: "...fg"},
		{content: "abcdefg", length: 5, clip: ClipMiddle, want: "a...g"},
		{content: "a", length: 5, clip: ClipLeft, want: "a"},
		{content: "abc", length: 5, clip: ClipLeft, want: "abc"},
		{content: "abcde", length: 5, clip: ClipLeft, want: "abcde"},
		{content: "abcde", length: 2, clip: ClipLeft, want: "ab"},
		{content: "abcde", length: 2, clip: ClipRight, want: "de"},
	}

	for _, testCase := range testTable {
		summarizedContent := Summarize(testCase.content, testCase.length, testCase.clip)
		t.Log(summarizedContent)
		if summarizedContent != testCase.want {
			t.Fatalf("given: %s len %d want: %s got: %s", testCase.content, testCase.length, testCase.want, summarizedContent)
		}
	}
}

func TestPrettyPrintMap(t *testing.T) {
	obj := map[string]string{"Key A": "Value A", "Key B": "Value B"}
	t.Log(PrettyPrintMap(obj))
}
