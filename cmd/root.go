/*
Copyright © 2020 Ian Kirker

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

var cfgFile string
var logLevel string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "keyscan",
	Short: "A tool for finding duplicated user public keys",
	Long: `keyscan is a tool to scan authorized_keys files and report
		duplicates and forbidden keys.
		`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) { runScan() },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: /etc/keyscan/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log_level", "l", "logging level (panic|fatal|error|warn|info|debug|trace) (default: warn)")

	if err := viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log_level")); err != nil {
		log.Fatal("Internal problem: unable to bind flag:", err)
	}

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in /etc/keyscan
		viper.AddConfigPath("/etc/keyscan")
		viper.SetConfigName("config.yaml")
	}

	viper.SetDefault("target_globs", []string{"/home/*/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys2"})
	viper.SetDefault("permitted_key_files", []string{"/etc/keyscan/permitted_keys"})
	viper.SetDefault("forbidden_key_files", []string{"/etc/keyscan/forbidden_keys"})
	viper.SetDefault("ignored_owners", []string{})
	viper.SetDefault("lower_uid_bound", 500)
	viper.SetDefault("log_level", "warn")

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		setLogLevel(viper.GetString("log_level"))
		log.Info("Using config file:", viper.ConfigFileUsed())
	} else {
		setLogLevel(viper.GetString("log_level"))
		log.Warn("No config file found, using defaults")
	}
}

func setLogLevel(level string) {
	switch level {
	case "panic":
		log.SetLevel(log.PanicLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "trace":
		log.SetLevel(log.TraceLevel)
	default:
		log.Fatal("invalid logging level requested")
	}
}
