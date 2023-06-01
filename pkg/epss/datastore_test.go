package epss

import (
	"bytes"
	"errors"
	"math"
	"os"
	"testing"
)

const EPSS_TEST_FILE = "../../test/epss.csv"
const equalityThreshold = 1e-9

func TestCSVDecoder(t *testing.T) {
	store := NewDataStore()
	expected := [5]Vulnerability{
		{CVE: "CVE-2023-32071", Probability: 0.00096, Percentile: 0.39055},
		{CVE: "CVE-2023-33297", Probability: 0.00045, Percentile: 0.12326},
		{CVE: "CVE-1999-0008", Probability: 0.00389, Percentile: 0.69317},
		{CVE: "CVE-1999-0454", Probability: 0.00727, Percentile: 0.77947},
		{CVE: "CVE-2007-0798", Probability: 0.00431, Percentile: 0.70797},
	}

	f := MustOpen(EPSS_TEST_FILE, t)

	if err := NewCSVDecoder(f).Decode(store); err != nil {
		t.Fatal(err)
	}

	t.Run("success", func(t *testing.T) {
		if store.Len() < 10 {
			t.Fatal("Total Items:", store.Len())
		}

		for _, want := range expected {
			got, err := store.Get(want.CVE)
			if err != nil {
				t.Fatal(err)
			}
			if math.Abs(got.Probability-want.Probability) > equalityThreshold {
				t.Fatalf("Want: %.15f Got: %.15f\n", want.Probability, got.Probability)
			}
			if math.Abs(got.Percentile-want.Percentile) > equalityThreshold {
				t.Fatalf("Want: %.15f Got: %.15f\n", want.Percentile, got.Percentile)
			}
		}

	})

	t.Run("bad-values", func(t *testing.T) {
		store.data["bad-values"] = scores{Probability: "nil", Percentile: "0.0032"}
		if _, err := store.Get("non-existant"); errors.Is(err, ErrNotFound) != true {
			t.Fatal(err, "Expected Not Found")
		}
		if _, err := store.Get("bad-values"); errors.Is(err, ErrDecode) != true {
			t.Fatal(err, "Expected Decode Error")
		}
		store.data["bad-values"] = scores{Probability: "0.0035", Percentile: "nil"}
		if _, err := store.Get("bad-values"); errors.Is(err, ErrDecode) != true {
			t.Fatal(err, "Expected Decode Error")
		}
	})

	t.Run("bad-file", func(t *testing.T) {
		if err := NewCSVDecoder(bytes.NewBufferString("a,b,c")).Decode(&DataStore{}); !errors.Is(err, ErrDecode) {
			t.Fatal(err, "Expected Decode error")
		}
		badCSV := "cve,epss,percentile\n1,2,3,4,5"
		if err := NewCSVDecoder(bytes.NewBufferString(badCSV)).Decode(&DataStore{}); !errors.Is(err, ErrDecode) {
			t.Fatal(err, "Expected Decode error")
		}
	})
}

func TestDataStore_Write(t *testing.T) {
	store := NewDataStore()
	store.data["CVE-A"] = scores{Probability: "0.03234", Percentile: "0.11184"}
  
	t.Run("success", func(t *testing.T) {
		sample := Data{CVE: "CVE-A"}
		if err := store.Write(&sample); err != nil {
			t.Fatal(err)
		}
    if sample.Percentile != "0.11184" {
      t.Fail()
    }
	})

  t.Run("nil", func(t *testing.T) {
    if err := store.Write(nil); !errors.Is(err, ErrDecode) {
      t.Fatal(err, "Expected Decode Error")
    }
  })

  t.Run("not-found", func(t *testing.T) {
    if err := store.Write(&Data{CVE: "None"}); !errors.Is(err, ErrNotFound) {
      t.Fatal(err, "Expected Not Found Error")
    }
  })

}

func MustOpen(filename string, t *testing.T) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
