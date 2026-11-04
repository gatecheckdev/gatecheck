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
	// OSVScannerVersion is the google/osv-scanner GitHub release.
	OSVScannerVersion = "2.7.0"
	// GosecVersion is the securego/gosec GitHub release.
	GosecVersion = "2.30.0"
	// HadolintVersion is the hadolint/hadolint GitHub release.
	HadolintVersion = "2.15.1"
	// ZizmorVersion is the zizmorcore/zizmor GitHub release. zizmor publishes
	// no checksum file, so its digests are pinned in zizmorChecksums.
	ZizmorVersion = "1.32.0"
	// ScorecardVersion is the ossf/scorecard GitHub release.
	ScorecardVersion = "5.6.0"
	// TrufflehogVersion is the trufflesecurity/trufflehog GitHub release.
	TrufflehogVersion = "3.99.8"
	// CosignVersion is the sigstore/cosign GitHub release.
	CosignVersion = "3.1.4"
)

// zizmorChecksums are the SHA-256 digests of the ZizmorVersion release assets.
// Update them together with ZizmorVersion.
var zizmorChecksums = map[string]string{
	"zizmor-aarch64-apple-darwin.tar.gz":      "6efed18c4539a663fd3c851a2be9533fd8456c4e646d9416206da059154a0d3c",
	"zizmor-x86_64-apple-darwin.tar.gz":       "6983143c719ada6845a69cc4dd2bacc215f971662fecd8bbd2678388e5ce5969",
	"zizmor-aarch64-unknown-linux-gnu.tar.gz": "cb152b207f815116d7fa1c1ee4614f61578803351395052908095e79adfd9fd0",
	"zizmor-x86_64-unknown-linux-gnu.tar.gz":  "bb110cc765eca9cd7efb2e284a956be5974c60027b0970f16397d86208a9957b",
	"zizmor-x86_64-pc-windows-msvc.zip":       "d284a16e09d9df4ce2c000357e7b59bd531be093bea5718a1ce225b449b59d49",
}
