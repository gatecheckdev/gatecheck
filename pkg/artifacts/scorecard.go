package artifacts

// ScorecardReport is the part of `scorecard --format json` that gatecheck reads.
type ScorecardReport struct {
	Repo struct {
		Name   string `json:"name"`
		Commit string `json:"commit"`
	} `json:"repo"`
	Scorecard struct {
		Version string `json:"version"`
	} `json:"scorecard"`
	Score  float64          `json:"score"`
	Checks []ScorecardCheck `json:"checks"`
}

// ScorecardCheck is one Scorecard check. Score is 0 to 10, or -1 when the
// check could not run or does not apply.
type ScorecardCheck struct {
	Name          string  `json:"name"`
	Score         float64 `json:"score"`
	Reason        string  `json:"reason"`
	Documentation struct {
		URL string `json:"url"`
	} `json:"documentation"`
}

// Inconclusive reports whether the check has no score.
func (c ScorecardCheck) Inconclusive() bool { return c.Score < 0 }
