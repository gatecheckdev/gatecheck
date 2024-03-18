# Gatecheck Refactor

## Package Updates

The Async Decoder is no longer used for a number of reasons, mostly for code readability.
The user experience improvements and performance improvements were not enough to justify the complexity of the code 
required to keep it.

## Config Updates

The new configuration file is more expressive than the original with the ability the selectively enable/disable certain
rules.

See the (Configuration Guide)[./configuration.md] for details.

## New CLI

Gatecheck is currently going through a refactor which will give the CLI some much-needed love.
The more streamlined CLI will reduce the complexity with usage and provide a clear use case for every command.


## Deprecation Schedule

The existing Gatecheck CLI is now considered deprecated however, users can still access the legacy CLI by
setting the environment variable `GATECHECK_FF_LEGACY_CLI_ENABLED=1` as of version 0.4.0.

This Legacy CLI and packages are scheduled to be removed after version 0.5.0.
