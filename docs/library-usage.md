# Library Usage

The CLI is a thin wrapper around `github.com/gatecheckdev/gatecheck/pkg/gatecheck`.

```go
import "github.com/gatecheckdev/gatecheck/pkg/gatecheck"
```

- `NewDefaultConfig` returns the same defaults as `gatecheck config init`: rules disabled, coverage thresholds `0`.
- `NewConfigDecoder` reads `.yaml`, `.yml`, `.json`, or `.toml`. The extension selects the format. When the file has keys gatecheck does not read, `Decode` still fills the config and returns an error wrapping `ErrUnknownConfigKeys`. Check it with `errors.Is` and treat it as a warning. `DecodeConfig` does the same for bytes you already have.
- `EncodeConfigTo` and `NewConfigEncoder` write a config as `json`, `yaml`, `yml`, or `toml`, with or without the dot. JSON and YAML are indented by two spaces. `ConfigFormat` checks a format name.
- `Validate` takes the config, a reader, and the filename. The bytes select the report type. The filename is the fallback, with the same words as the CLI.
- `List` writes a table. `WithDisplayFormat` takes `table`, `markdown`, or `json`. A Grype, CycloneDX, SARIF, Semgrep, Gitleaks, Trivy, or osv-scanner report with no findings writes one sentence instead, such as `No gitleaks findings`, `No trivy vulnerabilities`, or `No osv-scanner vulnerabilities`. `WithDisplayFormat("markdown")` matches `--markdown` and writes that same sentence when the report is empty. `WithEPSS` matches `--epss` and takes an open CSV file or a URL.
- `CreateBundle`, `AppendToBundle`, and `RemoveFromBundle` are `bundle create`, `bundle add`, and `bundle remove`.
- `DownloadEPSS` and `DownloadKEV` write the API payloads. `WithEPSSURL`, `WithKEVURL`, `WithEPSSFile`, and `WithKEVFile` override the defaults. `WithVEXFiles` adds VEX documents to `Validate`.
- Errors: `ErrValidationFailure` is a threshold failure. `ErrExternalData` means EPSS or KEV data could not be loaded. `ErrBundleLabelNotFound` comes from `RemoveFromBundle`. The CLI maps these to exit codes 1, 3, and 2 with `cmd.ExitCode`.

Report types are described in [Supported Reports](./supported-reports.md). Config fields are described in [Configuration](./configuration.md).
