package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// Settings are read flag first, then environment variable, then the flag's
// default. An empty environment variable counts as unset.

func envValue(env string) (string, bool) {
	if env == "" {
		return "", false
	}
	v, ok := os.LookupEnv(env)
	if !ok || strings.TrimSpace(v) == "" {
		return "", false
	}
	return strings.TrimSpace(v), true
}

func stringSetting(cmd *cobra.Command, flag, env string) string {
	f := cmd.Flags().Lookup(flag)
	if f != nil && f.Changed {
		return f.Value.String()
	}
	if v, ok := envValue(env); ok {
		return v
	}
	if f != nil {
		return f.Value.String()
	}
	return ""
}

func boolSetting(cmd *cobra.Command, flag, env string) (bool, error) {
	f := cmd.Flags().Lookup(flag)
	if f != nil && f.Changed {
		return strconv.ParseBool(f.Value.String())
	}
	if v, ok := envValue(env); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return false, fmt.Errorf("%s=%q is not a boolean (use true or false)", env, v)
		}
		return b, nil
	}
	if f != nil {
		return strconv.ParseBool(f.Value.String())
	}
	return false, nil
}

func stringSliceSetting(cmd *cobra.Command, flag, env string) []string {
	f := cmd.Flags().Lookup(flag)
	if f != nil && f.Changed {
		values, _ := cmd.Flags().GetStringSlice(flag)
		return values
	}
	if v, ok := envValue(env); ok {
		var out []string
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
		return out
	}
	if f != nil {
		values, _ := cmd.Flags().GetStringSlice(flag)
		return values
	}
	return nil
}

func oneOf(name, value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return fmt.Errorf("invalid %s %q, must be one of %s", name, value, strings.Join(allowed, ", "))
}
