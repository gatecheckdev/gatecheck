package bootstrap

// Pinned scanner versions installed by `gatecheck bootstrap`.
// Change the constants in this file to move the defaults.
const (
	// GrypeVersion is the anchore/grype GitHub release.
	GrypeVersion = "0.121.0"
	// SyftVersion is the anchore/syft GitHub release.
	SyftVersion = "1.55.0"
	// GitleaksVersion is the gitleaks/gitleaks GitHub release.
	GitleaksVersion = "8.30.1"
	// SemgrepVersion is the semgrep wheel on PyPI. The wheel's native
	// semgrep-core binary is installed as osemgrep.
	SemgrepVersion = "1.182.1"
	// TrivyVersion is the aquasecurity/trivy GitHub release.
	TrivyVersion = "0.76.1"
)
