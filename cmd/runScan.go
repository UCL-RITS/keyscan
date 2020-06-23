package cmd

import (
	"github.com/UCL-RITS/keyscan/internal/keyscan"
	"github.com/spf13/viper"
)

func runScan() {
	// This is the default, and only, command.
	p := keyscan.ScanParams{
		TargetGlobs:       viper.GetStringSlice("target_globs"),
		PermittedKeyFiles: viper.GetStringSlice("permitted_key_files"),
		ForbiddenKeyFiles: viper.GetStringSlice("forbidden_key_files"),
		IgnoredOwners:     viper.GetStringSlice("ignored_owners"),
		LowerUIDBound:     viper.GetInt("lower_uid_bound"),
	}

	ctx := &keyscan.ScanContext{Params: p}

	ctx.Go()
}
