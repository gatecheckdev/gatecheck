# Agents

This file is for agents changing the gatecheck repository. To use the gatecheck CLI, run `gatecheck agent-guide` (alias `llm`). The same text is `docs/agent-guide.md`, and `skills/gatecheck/SKILL.md` points at that command.

## Build, test, lint

- Build: `go build -o ./bin/gatecheck ./cmd/gatecheck`, or `task build`. The binary is `./bin/gatecheck`.
- Test: `go test ./...`, or `task test`.
- Vet: `go vet ./...`.
- Lint: `task lint` runs `golangci-lint run`. CI uses golangci-lint v2.15.0 with `.golangci.yaml`.
- Format: `gofmt -w` on edited Go files. `task format` fails when any file differs.
- Module: Go 1.26 (`go.mod`). CI tests Go 1.26 and 1.27.
- `task install` asks for confirmation before copying the binary to `INSTALL_DIR`.

## Layout

- `cmd/`: Cobra commands. `cmd/gatecheck` is `main`. `new<Name>Command` wires flags. Command behavior that is not flag parsing lives in `pkg/gatecheck`.
- `internal/fetch`: download and SHA-256 checks. `internal/bootstrap`: scanner install and passthrough. Pinned versions are the constants in `internal/bootstrap/versions.go`.
- `pkg/`: report decoding, validation, bundles, EPSS, and KEV.
- `docs/`: mdBook source for docs.gatecheck.dev. `docs/agent-guide.md` is the agent guide embedded by `docs/embed.go`.
- `website/`: static files for gatecheck.dev.
- `skills/gatecheck/SKILL.md`: skill for agents using the CLI.

## Conventions

- Check `gatecheck <command> --help` before describing a flag. `docs/cli-reference.md` matches the CLI on main.
- Report type is detected from file contents. A lowercase filename substring is the fallback when the contents are ambiguous. See `docs/supported-reports.md`.
- Coverage thresholds and EPSS scores are ratios from 0 to 1.
- Exit codes from `cmd/gatecheck`: 0 success, 1 threshold failure (`gatecheck.ErrValidationFailure`), 255 any other error (`os.Exit(-1)`). `grype`, `syft`, `gitleaks`, `semgrep`, `osemgrep`, `trivy`, and `osv-scanner` return the scanner's status. A missing scanner still exits 255.
- Do not add copyright notices.
