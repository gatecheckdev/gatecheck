package entity

import (
	"github.com/zricethezav/gitleaks/v8/report"
)

type GitleaksFinding report.Finding

type GitLeaksScanReport []GitleaksFinding
