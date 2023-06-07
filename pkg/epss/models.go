package epss

import (
	"errors"
	"time"
)

type CVE struct {
	ID          string
	Severity    string
	Link        string
	ScoreDate   time.Time
	Probability float64
	Percentile  float64
}


// An estimate for how many lines are in the CSV file for performance
const estimatedLineCount = 250_000

// The model supported from the First API
const supportedModel = "v2023.03.01"

// The date format to convert to
const modelDateLayout = "2006-01-02T15:04:05-0700"

var ErrDecode = errors.New("Decoding Error")
var ErrEncode = errors.New("Encoding failed")
var ErrNotFound = errors.New("CVE not found in Data Store")
var ErrAPIPartialFail = errors.New("an API request failed")
