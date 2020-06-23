package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func GetParamsFromConfig(filename string) ScanParams {
	v := viper.New()
	v.SetConfigName("config.yaml")   // name of config file
	v.SetConfigType("yaml")          // REQUIRED if the config file does not have the extension in the name
	v.AddConfigPath("/etc/keyscan/") // path to look for the config file in
	v.AddConfigPath("./")            // path to look for the config file in
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			log.Fatal(err)
		} else {
			// Config file was found but another error was produced
			log.Fatal(err)
		}
	}

	v.SetDefault("target_globs", []string{"/home/*/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys2"})
	v.SetDefault("permitted_key_files", []string{"/etc/keyscan/permitted_keys"})
	v.SetDefault("forbidden_key_files", []string{"/etc/keyscan/forbidden_keys"})
	v.SetDefault("ignored_owners", []string{})
	v.SetDefault("lower_uid_bound", 500)

	p := ScanParams{
		TargetGlobs:       v.GetStringSlice("target_globs"),
		PermittedKeyFiles: v.GetStringSlice("permitted_key_files"),
		ForbiddenKeyFiles: v.GetStringSlice("forbidden_key_files"),
		IgnoredOwners:     v.GetStringSlice("ignored_owners"),
		LowerUIDBound:     v.GetInt("lower_uid_bound"),
	}

	return p
}
