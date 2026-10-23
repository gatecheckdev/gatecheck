# Library Usage

The CLI is a thin wrapper around `github.com/gatecheckdev/gatecheck/pkg/gatecheck`.

```go
import "github.com/gatecheckdev/gatecheck/pkg/gatecheck"
```

- `NewDefaultConfig` returns the same defaults as `gatecheck config init`: rules disabled, coverage thresholds `0`.
- `NewConfigDecoder` reads `.yaml`, `.yml`, `.json`, or `.toml`. The extension selects the format.
- `NewConfigEncoder` writes a config. Pass `.yaml`, `.yml`, `.json`, or `.toml`, including the dot.
- `Validate` takes the config, a reader, and the filename. The filename selects the report type with the same words as the CLI.
- `List` writes a table. A Grype, CycloneDX, Semgrep, Gitleaks, or Trivy report with no findings writes one sentence instead, such as `No gitleaks findings` or `No trivy vulnerabilities`. `WithDisplayFormat("markdown")` matches `--markdown` and writes that same sentence when the report is empty. `WithEPSS` matches `--epss` and takes an open CSV file or a URL.
- `CreateBundle`, `AppendToBundle`, and `RemoveFromBundle` are `bundle create`, `bundle add`, and `bundle remove`.
- `DownloadEPSS` and `DownloadKEV` write the API payloads. `WithEPSSURL`, `WithKEVURL`, `WithEPSSFile`, and `WithKEVFile` override the defaults.

Report types and the filename words are described in [Supported Reports](./supported-reports.md). Config fields are described in [Configuration](./configuration.md).
