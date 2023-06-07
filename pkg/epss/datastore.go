package epss

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/log"
)

type scores struct {
	Probability string
	Percentile  string
}

type DataStore struct {
	data         map[string]scores
	modelVersion string
	scoreDate    time.Time
}

func NewDataStore() *DataStore {
	return &DataStore{data: make(map[string]scores, estimatedLineCount)}
}

func (d *DataStore) WriteEPSS(cves []CVE) error {
	for i := range cves {
		scores, ok := d.data[cves[i].ID]
		if !ok {
			return fmt.Errorf("%w: '%s'", ErrNotFound, cves[i].ID)
		}

		prob, perc, err := parseScores(scores)
		if err != nil {
			return fmt.Errorf("%w: '%s'", ErrDecode, cves[i].ID)
		}
		cves[i].ScoreDate = d.ScoreDate()
		cves[i].Probability = prob
		cves[i].Percentile = perc
	}
	log.Infof("%d CVEs EPSS Scores Updated", len(cves))

	return nil
}

func (d *DataStore) Len() int {
	return len(d.data)
}

func (d *DataStore) ScoreDate() time.Time {
	return d.scoreDate
}

func parseScores(s scores) (prob float64, perc float64, err error) {
	var res [2]float64

	for i, arg := range []string{s.Probability, s.Percentile} {
		value, err := strconv.ParseFloat(arg, 64)
		if err != nil {
			return 0, 0, err
		}
		res[i] = value
	}
	return res[0], res[1], nil
}

type CSVDecoder struct {
	r io.Reader
}

func NewCSVDecoder(r io.Reader) *CSVDecoder {
	return &CSVDecoder{r: r}
}

func (c *CSVDecoder) Decode(store *DataStore) error {
	defer func(started time.Time) { log.Infof("EPSS CSV decoding completed in %s", time.Since(started).String()) }(time.Now())
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
