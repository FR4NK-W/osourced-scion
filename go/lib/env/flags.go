// Copyright 2018 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package env

import (
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/scionproto/scion/go/lib/config"
)

var (
	configFile        string
	helpConfig        bool
	interactiveConfig string
	version           bool
)

// AddFlags adds the config and sample flags.
func AddFlags() {
	flag.StringVar(&configFile, "config", "", "TOML config file.")
	flag.BoolVar(&helpConfig, "help-config", false, "Output sample commented config file.")
	flag.StringVar(&interactiveConfig, "interactive-config", "", "Write config file " +
		"with user provided values.")
	flag.BoolVar(&version, "version", false, "Output version information and exit.")
}

// ConfigFile returns the config file path passed through the flag.
func ConfigFile() string {
	return configFile
}

// Usage outputs run-time help to stdout.
func Usage() {
	fmt.Printf("Usage: %s -config <FILE> \n   " +
		"or: %s {-help-config|-interactive-config}\n\nArguments:\n",
		os.Args[0], os.Args[0])
	flag.CommandLine.SetOutput(os.Stdout)
	flag.PrintDefaults()
}

// CheckFlags checks whether the config, interactive-config or help-config flags have been set.
// In case the either the help-config flag or interactive-config are set, the config flag is ignored
// and a commented sample config is written to stdout or the config is created with the values provided
// interactively.
//
// The first return value is the return code of the program. The second value
// indicates whether the program can continue with its execution or should exit.
func CheckFlags(configurator config.Config) (int, bool) {
	if helpConfig {
		configurator.Sample(os.Stdout, nil, nil)
		return 0, false
	}
	if interactiveConfig != "" {
		err := os.MkdirAll(path.Dir(interactiveConfig), os.FileMode(0655))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Err: Failed to create output file %s directory.\n",
				path.Dir(interactiveConfig))
		}
		f, err := os.OpenFile(interactiveConfig,
			os.O_CREATE|os.O_WRONLY, os.FileMode(0644))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Err: Failed to create config output file %s.\n", interactiveConfig)
		}
		configurator.Configure(f)
		return 0, false
	}
	if version {
		fmt.Printf(VersionInfo())
		return 0, false
	}
	if configFile == "" {
		fmt.Fprintln(os.Stderr, "Err: Missing config file")
		flag.Usage()
		return 1, false
	}
	return 0, true
}
