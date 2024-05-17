package cmd

import (
	"os"
	"strings"

	"github.com/gatecheckdev/configkit"
	"github.com/spf13/cobra"
)

var (
	metadataFlagUsage       = "flag_usage"
	metadataFieldType       = "field_type"
	metadataRequired        = "required"
	metadataActionInputName = "action_input_name"
)

type Config struct {
	BundleTag string
}

type metaConfig struct {
	BundleTag      configkit.MetaField
	BundleTagValue []string
	bundleFile     *os.File
	targetFile     *os.File
}

var RuntimeConfig = metaConfig{
	BundleTag: configkit.MetaField{
		FieldName:    "BundleTag",
		EnvKey:       "GATECHECK_BUNDLE_TAG",
		DefaultValue: "",
		FlagValueP:   new([]string),
		EnvToValueFunc: func(s string) any {
			return strings.Split(s, ",")
		},
		Metadata: map[string]string{
			metadataFlagUsage:       "file properties for metadata",
			metadataFieldType:       "string",
			metadataActionInputName: "bundle_tag",
		},
		CobraSetupFunc: func(f configkit.MetaField, cmd *cobra.Command) {
			valueP := f.FlagValueP.(*[]string)
			usage := f.Metadata["flag_usage"]
			cmd.Flags().StringSliceVarP(valueP, "tag", "t", []string{}, usage)
		},
	},
}
