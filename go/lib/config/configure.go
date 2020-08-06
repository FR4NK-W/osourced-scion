// Copyright 2020 ETH Zurich
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

package config

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/BurntSushi/toml"
)

// WriteErrorMsg writes an error message
func WriteErrorMsg(dst io.Writer, msg string) {
	fmt.Fprintln(dst, msg)
}

// WriteConfiguration writes all configured config blocks
func WriteConfiguration(dst io.Writer, configurators ...Config) {
	var buf bytes.Buffer
	for _, configurator := range configurators {
		toml.NewEncoder(&buf).Encode(configurator)
		fmt.Fprint(dst, buf.String())
		buf.Reset()
	}
}

type PromptReader struct {
	Reader bufio.Reader
}

// NewPromptReader returns a new PromptReader
func NewPromptReader(rd io.Reader) *PromptReader {
	reader := bufio.NewReader(rd)
	return &PromptReader{Reader: *reader}
}

func (p PromptReader) PromptRead(prompt string) (ret string, err error) {
	fmt.Printf(prompt)
	ret, err = p.Reader.ReadString('\n')
	ret = strings.TrimSpace(ret)
	return
}
