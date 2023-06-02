package epss

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)


type DataStore struct {
	data         map[string]scores
	modelVersion string
	scoreDate    time.Time
}

func NewDataStore() *DataStore {
	return &DataStore{data: make(map[string]scores, estimatedLineCount)}
}

func (d *DataStore) Get(cve string) (Vulnerability, error) {
	scores, ok := d.data[cve]

	if !ok {
		return Vulnerability{}, fmt.Errorf("%w: '%s'", ErrNotFound, cve)
	}
	prob, err := strconv.ParseFloat(scores.Probability, 64)
	if err != nil {
		return Vulnerability{}, fmt.Errorf("%w: '%s'", ErrDecode, scores.Probability)
	}
	perc, err := strconv.ParseFloat(scores.Percentile, 64)
	if err != nil {
		return Vulnerability{}, fmt.Errorf("%w: '%s'", ErrDecode, scores.Percentile)
	}
	return Vulnerability{CVE: cve, Probability: prob, Percentile: perc}, nil
}

func (d *DataStore) Write(dataObj *Data) error {
	if dataObj == nil {
		return fmt.Errorf("%w: target is nil", ErrDecode)
	}
	scores, ok := d.data[dataObj.CVE]

	if !ok {
		return fmt.Errorf("%w: '%s'", ErrNotFound, dataObj.CVE)
	}
	dataObj.EPSS = scores.Probability
	dataObj.Percentile = scores.Percentile

	return nil
}

func (d *DataStore) Len() int {
	return len(d.data)
}

func (d *DataStore) ScoreDate() time.Time {
	return d.scoreDate
}

type scores struct {
	Probability string
	Percentile  string
}

type CSVDecoder struct {
	r io.Reader
}

func NewCSVDecoder(r io.Reader) *CSVDecoder {
	return &CSVDecoder{r: r}
}

func (c *CSVDecoder) Decode(store *DataStore) error {
	scanner := bufio.NewScanner(c.r)

	scanner.Scan()
	parts := strings.Split(scanner.Text(), ",")
	if len(parts) != 2 {
		return fmt.Errorf("%w: CSV Reader detected malformed metadata header: '%s'", ErrDecode, scanner.Text())
	}

	store.modelVersion = strings.ReplaceAll(parts[0], "#model_version:", "")

	if store.modelVersion != supportedModel {
		return fmt.Errorf("%w: CSV Reader detected invalid model version: '%s'", ErrDecode, scanner.Text())
	}

	sDate, err := time.Parse(modelDateLayout, strings.ReplaceAll(parts[1], "score_date:", ""))
	if err != nil {
		return fmt.Errorf("%w: CSV Reader detected invalid date format in metadata: '%s'", ErrDecode, scanner.Text())
	}
	store.scoreDate = sDate

	// Next Line should be header
	scanner.Scan()

	if scanner.Text() != "cve,epss,percentile" {
		return fmt.Errorf("%w: CSV Reader detected malformed header: '%s'", ErrDecode, scanner.Text())
	}

	for scanner.Scan() {
		line := scanner.Text()
		// Add the newline back in so it would make a full file hash
		values := strings.Split(line, ",")

		if len(values) != 3 {
			return fmt.Errorf("%w: CSV Reader detected malformed data: %s", ErrDecode, values)
		}

		store.data[values[0]] = scores{Probability: values[1], Percentile: values[2]}
	}
	return nil
}
