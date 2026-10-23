// Package docs embeds the agent guide printed by the CLI.
package docs

import _ "embed"

// AgentGuide is the markdown printed by gatecheck agent-guide.
//
//go:embed agent-guide.md
var AgentGuide string
