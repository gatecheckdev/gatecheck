package entity

// Manually implemented from ATD schema on 3 Oct 2022
// https://github.com/returntocorp/semgrep-interfaces/blob/ee75cb212500f2a57ef5938013a4955a84bb9ab1/semgrep_output_v0.atd

// SemgrepScanReport is a data model for a Semgrep Output scan produced by `semgrep scan --json`
type SemgrepScanReport struct {
	Errors []struct {
		Code         int    `json:"code"`
		Level        string `json:"level"`
		Type         string `json:"type"`
		RuleID       string `json:"rule_id"`
		Message      string `json:"message"`
		Path         string `json:"path"`
		LongMessage  string `json:"long_message"`
		ShortMessage string `json:"short_message"`
		Span         []struct {
			File         string             `json:"file"`
			Start        semgrepPositionBis `json:"start"`
			End          semgrepPositionBis `json:"end"`
			SourceHash   string             `json:"sourceHash"`
			ConfigStart  semgrepPositionBis `json:"config_start"`
			ConfigEnd    semgrepPositionBis `json:"config_end"`
			ConfigPath   string             `json:"config_path"`
			ContextStart semgrepPositionBis `json:"context_start"`
			ContextEnd   semgrepPositionBis `json:"context_end"`
		}
		Help string `json:"help"`
	} `json:"errors"`
	Results []struct {
		CheckID string `json:"check_id"`
		semgrepLocation
		Extra struct {
			Metavars    map[string]interface{} `json:"metavars"`
			Fingerprint string                 `json:"fingerprint"`
			Lines       string                 `json:"lines"`
			Message     string                 `json:"message"`
			Metadata    map[string]interface{} `json:"metadata"`
			Severity    string                 `json:"severity"`
			Fix         string                 `json:"fix"`
			FixRegex    string                 `json:"fix_regex"`
			IsIgnored   bool                   `json:"is_ignored"`
			SCAInfo     struct {
				Reachable        bool `json:"reachable"`
				ReachabilityRule bool `json:"reachability_rule"`
				SCAFindingSchema int  `json:"sca_finding_schema"`
				DependencyMatch  struct {
					DependencyPattern struct {
						Ecosystem   interface{} `json:"ecosystem"`
						Package     string      `json:"package"`
						SemverRange string      `json:"semver_range"`
					} `json:"dependency_pattern"`
					FoundDependency struct {
						Package       string      `json:"package"`
						Version       string      `json:"version"`
						Ecosystem     interface{} `json:"ecosystem"`
						AllowedHashes interface{} `json:"allowed_hashes"`
						ResolvedURL   string      `json:"resolved_url"`
						Transitivity  interface{} `json:"transitivity"`
						LineNumber    int         `json:"line_number"`
					} `json:"found_dependency"`
					Lockfile string `json:"lockfile"`
				} `json:"dependency_match"`
			} `json:"sca_info"`
			FixedLines    []string `json:"fixed_lines"`
			DataflowTrace struct {
				TaintSource struct {
					Location semgrepLocation `json:"location"`
					Content  string          `json:"content"`
				} `json:"taint_source"`
				IntermediateVars struct {
					Location semgrepLocation `json:"location"`
					Content  string          `json:"content"`
				} `json:"intermediate_vars"`
			} `json:"dataflow_trace"`
		} `json:"extra"`
	} `json:"results"`
	Paths struct {
		Scanned []string `json:"scanned"`
		Comment string   `json:"_comment"`
		Skipped struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	} `json:"paths"`
	Time struct {
		Rules []struct {
			ID string `json:"ID"`
		} `json:"rules"`
		RulesParseTime float32     `json:"rules_parse_time"`
		ProfilingTimes interface{} `json:"profiling_times"`
		Targets        []struct {
			Path       string  `json:"path"`
			NumBytes   int     `json:"num_bytes"`
			MatchTimes float32 `json:"match_times"`
			ParseTimes float32 `json:"parse_times"`
			RunTime    float32 `json:"run_time"`
		} `json:"targets"`
		TotalBytes int `json:"total_bytes"`
	} `json:"time"`
	Explanations semgrepExplanation `json:"explanations"`
	Version      string             `json:"version"`
}

type semgrepExplanation struct {
	Op       interface{}          `json:"op"`
	Children []semgrepExplanation `json:"children"`
	Matches  []struct {
		RuleID   string          `json:"ruleID"`
		Location semgrepLocation `json:"location"`
		Extra    struct {
			Message       string      `json:"message"`
			Metavars      interface{} `json:"metavars"`
			DataflowTrace struct {
				TaintSource      semgrepLocation `json:"taint_source"`
				IntermediateVars []struct {
					Location semgrepLocation `json:"location"`
				} `json:"intermediate_vars"`
			} `json:"dataflow_trace"`
			RenderedFix string `json:"rendered_fix"`
		} `json:"extra"`
	} `json:"matches"`
	Loc semgrepLocation `json:"loc"`
}

type semgrepPosition struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

type semgrepPositionBis struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepLocation struct {
	Path  string          `json:"path"`
	Start semgrepPosition `json:"start"`
	End   semgrepPosition `json:"end"`
}
