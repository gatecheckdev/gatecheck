# CLI Reference

Global flags, accepted on every command:

- `-v`, `--verbose`: print debug logs.
- `--silent`: hide debug, info, and warning logs. Errors are still printed.
- `-h`, `--help`: help for that command.

`--verbose` and `--silent` cannot be set together.

When a setting has both a flag and an environment variable, a non-empty flag wins. An empty flag falls through to the environment variable, then to the default.

## gatecheck

```
gatecheck [flags]
gatecheck [command]
```

With no arguments, the command prints nothing and exits 0.

- `--version`: print the same build information as `gatecheck version`. This flag is only on the root command.

## gatecheck version

```
gatecheck version
```

Prints the logo and the build information: CLI version, git commit, build date, git description, platform, Go version, and compiler. A build that does not pass those values prints `[Not Provided]`.

## gatecheck config init

```
gatecheck config init
```

Prints a default config to standard output. Every rule is disabled and every coverage threshold is `0`.

- `-o`, `--output`: `json`, `.json`, `toml`, `.toml`, `yaml`, `yml`, `.yaml`, or `.yml`. The default is `yaml`. Any other value is an error. The match is case sensitive.

```shell
gatecheck config init > gatecheck.yaml
gatecheck config init --output json > gatecheck.json
```

## gatecheck config convert

```
gatecheck config convert
```

Reads a config file and prints it in another format.

- `-f`, `--file`: file to read. The default is `gatecheck.yaml`. The extension picks the decoder (`.yaml`, `.yml`, `.json`, `.toml`).
- `-o`, `--output`: format to write. Same accepted values as `config init`. The default is `yaml`.

```shell
gatecheck config convert --file gatecheck.yaml --output toml
```

## gatecheck list

```
gatecheck list [FILE]
```

Aliases: `ls`, `print`.

Prints a table for one report. The first filename is the one that is opened. Further filenames are ignored. Use `list-all` for more than one file.

With no filename, the command reads standard input and `--input-type` is required.

- `-i`, `--input-type`: type word used when reading standard input. It is matched with the same rules as a filename. `grype`, `cyclonedx`, `semgrep`, `gitleaks`, `syft`, `bundle`, and the coverage words all work. See [Supported Reports](./supported-reports.md).
- `--markdown`: print a markdown table.
- `--epss`: add EPSS score and percentile columns. This changes the table for Grype and CycloneDX. Other report types still list, and the EPSS data is not shown. With no local file, gatecheck downloads the current EPSS CSV and caches it until the published date changes. Requests send a User-Agent with the gatecheck version and project URL.
- `--epss-filename`: read that CSV instead of calling the API. `GATECHECK_EPSS_FILENAME` is the same setting.
- `--epss-url`: EPSS API URL. An empty value uses `https://epss.cyentia.com`. `GATECHECK_EPSS_URL` is the same setting.
- `--epss-cache-dir`: cache directory for that download. `GATECHECK_EPSS_CACHE_DIR` is the same setting.
- `--epss-no-cache`: download on every run. `GATECHECK_EPSS_CACHE=off` does the same.

```shell
gatecheck list grype-report.json
gatecheck list --markdown --epss grype-report.json
grype bkimminich/juice-shop:latest -o json | gatecheck ls --input-type grype
```

## gatecheck list-all

```
gatecheck list-all [FILE...]
```

Prints each filename, then its table. A file whose name is not a supported `list-all` type is skipped with a warning. A missing file is skipped. A list error is logged and the command continues. The command exits 0 after the last file.

- `--markdown`: print markdown tables.
- `--epss`: download EPSS data and add it for filenames that contain `grype` or `cyclonedx`. The download happens per file and is cached until the published date changes. There is no `--epss-filename` flag. `GATECHECK_EPSS_URL` overrides the API. `GATECHECK_EPSS_FILENAME` is not read by this command. Requests send a User-Agent with the gatecheck version and project URL.
- `--epss-cache-dir`: cache directory for that download. `GATECHECK_EPSS_CACHE_DIR` is the same setting.
- `--epss-no-cache`: download on every run. `GATECHECK_EPSS_CACHE=off` does the same.

## gatecheck validate

```
gatecheck validate [FILE]
```

`FILE` is required. The config is a flag.

- `-f`, `--config`: config file. `GATECHECK_CONFIG_FILENAME` is the same setting. With neither, the built-in default config is used (every rule disabled, coverage thresholds `0`).
- `--epss-filename`: EPSS CSV to use when an EPSS rule is enabled. `GATECHECK_EPSS_FILENAME` is the same setting.
- `--epss-cache-dir`: cache directory used when that CSV is downloaded. `GATECHECK_EPSS_CACHE_DIR` is the same setting.
- `--epss-no-cache`: download on every run. `GATECHECK_EPSS_CACHE=off` does the same.
- `--kev-filename`: CISA KEV JSON to use when a KEV rule is enabled.
- `-a`, `--audit`: print the error from the check and exit 0. A missing report, a missing config, or a bad flag still exits 255.

`validate` has no `--epss-url` or `--kev-url` flag. `GATECHECK_EPSS_URL` and `GATECHECK_KEV_URL` still override those APIs when the matching file flag is empty. The defaults are the same URLs `download` uses.

EPSS data is loaded only when an EPSS limit or EPSS risk acceptance rule is enabled. When `--epss-filename` is not set, gatecheck downloads the current EPSS file and caches it until the published date changes. Requests send a User-Agent with the gatecheck version and project URL.

KEV data is loaded only when `kevLimitEnabled` is true for Grype or CycloneDX.

```shell
gatecheck validate --config gatecheck.yaml grype-report.json
gatecheck validate --audit --config gatecheck.yaml gatecheck-bundle.tar.gz
```

See [Validation](./validation.md) for rule order and exit codes.

## gatecheck bundle create

```
gatecheck bundle create BUNDLE_FILE TARGET_FILE
```

Alias: `init`.

Creates a bundle and stores the target file in it. The label is the base name of the target file (`reports/grype-report.json` is stored as `grype-report.json`).

- `-t`, `--tag`: tag stored on that file. Repeat the flag for more than one tag. `GATECHECK_BUNDLE_TAG` is a comma-separated list used when no tag flag is passed.

```shell
gatecheck bundle create gatecheck-bundle.tar.gz grype-report.json --tag ci
```

## gatecheck bundle add

```
gatecheck bundle add BUNDLE_FILE TARGET_FILE
```

Adds another file to an existing bundle. The label is the base name of the target file. `--tag` and `GATECHECK_BUNDLE_TAG` work the same way as on `bundle create`.

## gatecheck bundle remove

```
gatecheck bundle remove BUNDLE_FILE LABEL
```

Alias: `rm`.

Deletes the file with that label. The label is the base name used when the file was added, not a path that is opened. A label that is not in the bundle is logged and the command still exits 0.

## gatecheck download epss

```
gatecheck download epss
```

Writes the FIRST.org EPSS CSV to standard output.

EPSS scores are cached in the user cache directory, under `gatecheck/epss`. gatecheck checks the redirect to the dated filename and downloads the CSV only when that file is not already cached. Requests send a User-Agent with the gatecheck version and project URL.

- `--epss-url`: API URL. An empty value uses `https://epss.cyentia.com`. `GATECHECK_EPSS_URL` is the same setting.
- `--epss-cache-dir`: cache directory. `GATECHECK_EPSS_CACHE_DIR` is the same setting.
- `--epss-no-cache`: download on every run. `GATECHECK_EPSS_CACHE=off` does the same.

```shell
gatecheck download epss > epss.csv
```

## gatecheck download kev

```
gatecheck download kev
```

Writes the CISA Known Exploited Vulnerabilities catalog as JSON to standard output.

- `--kev-url`: API URL. An empty value uses `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. `GATECHECK_KEV_URL` is the same setting.

```shell
gatecheck download kev > kev.json
```

## gatecheck agent-guide

```
gatecheck agent-guide
```

Alias: `llm`.

Prints a markdown guide for agents that run the CLI. The text is `docs/agent-guide.md`.

```shell
gatecheck agent-guide
gatecheck llm
```

## gatecheck completion

```
gatecheck completion bash
gatecheck completion fish
gatecheck completion powershell
gatecheck completion zsh
```

Prints a completion script for that shell.

## gatecheck help

```
gatecheck help [command]
```

Prints help for a command. `gatecheck validate --help` does the same.

## Environment variables

| Variable | Commands | Same as |
| --- | --- | --- |
| `GATECHECK_CONFIG_FILENAME` | `validate` | `--config` |
| `GATECHECK_EPSS_FILENAME` | `list`, `validate` | `--epss-filename` |
| `GATECHECK_EPSS_URL` | `download epss`, `list`, `list-all`, `validate` | `--epss-url` on `download epss` and `list` |
| `GATECHECK_EPSS_CACHE_DIR` | `download epss`, `list`, `list-all`, `validate` | `--epss-cache-dir` |
| `GATECHECK_EPSS_CACHE` | `download epss`, `list`, `list-all`, `validate` | `--epss-no-cache` when the value is `off` |
| `GATECHECK_KEV_URL` | `download kev`, `validate` | `--kev-url` on `download kev` |
| `GATECHECK_BUNDLE_TAG` | `bundle create`, `bundle add` | `--tag`, as a comma-separated list |
