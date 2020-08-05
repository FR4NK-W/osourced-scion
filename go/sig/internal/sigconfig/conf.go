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

package sigconfig

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

const (
	DefaultCtrlPort    = 30256
	DefaultEncapPort   = 30056
	DefaultTunName     = "sig"
	DefaultTunRTableId = 11
)

type Config struct {
	Features env.Features
	Logging  log.Config       `toml:"log,omitempty"`
	Metrics  env.Metrics      `toml:"metrics,omitempty"`
	Sciond   env.SCIONDClient `toml:"sciond_connection,omitempty"`
	Sig      SigConf          `toml:"sig,omitempty"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Sciond,
		&cfg.Sig,
	)
}

func (cfg *Config) Configure(dst io.Writer) {
	cfg.InitDefaults()
	err := config.ConfigureAll(dst,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Sciond,
		&cfg.Sig,
	)
	if err != nil {
		config.WriteErrorMsg(dst, err.Error())
		return
	}
	config.WriteConfiguration(dst, cfg)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Sciond,
		&cfg.Sig,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Sciond,
		&cfg.Sig,
	)
}

func (cfg *Config) ConfigName() string {
	return "sig_config"
}

var _ config.Config = (*SigConf)(nil)

// SigConf contains the configuration specific to the SIG.
type SigConf struct {
	// ID of the SIG (required)
	ID string `toml:"id,omitempty"`
	// The SIG config json file. (required)
	SIGConfig string `toml:"sig_config,omitempty"`
	// IA the local IA (required)
	IA addr.IA `toml:"isd_as,omitempty"`
	// IP the bind IP address (required)
	IP net.IP `toml:"ip,omitempty"`
	// Control data port, e.g. keepalives. (default DefaultCtrlPort)
	CtrlPort uint16 `toml:"ctrl_port,omitempty"`
	// Encapsulation data port. (default DefaultEncapPort)
	EncapPort uint16 `toml:"encap_port,omitempty"`
	// Name of TUN device to create. (default DefaultTunName)
	Tun string `toml:"tun,omitempty"`
	// TunRTableId the id of the routing table used in the SIG. (default DefaultTunRTableId)
	TunRTableId int `toml:"tun_routing_table_id,omitempty"`
	// IPv4 source address hint to put into routing table.
	SrcIP4 net.IP `toml:"src_ipv4,omitempty"`
	// IPv6 source address hint to put into routing table.
	SrcIP6 net.IP `toml:"src_ipv6,omitempty"`
	// DispatcherBypass is the overlay address (e.g. ":30041") to use when bypassing SCION
	// dispatcher. If the field is empty bypass is not done and SCION dispatcher is used
	// instead.
	DispatcherBypass string `toml:"dispatcher_bypass,omitempty"`
}

// InitDefaults sets the default values to unset values.
func (cfg *SigConf) InitDefaults() {
}

// Validate validate the config and returns an error if a value is not valid.
func (cfg *SigConf) Validate() error {
	if cfg.ID == "" {
		return serrors.New("id must be set!")
	}
	if cfg.SIGConfig == "" {
		return serrors.New("sig_config must be set!")
	}
	if cfg.IA.IsZero() {
		return serrors.New("isd_as must be set")
	}
	if cfg.IA.IsWildcard() {
		return serrors.New("Wildcard isd_as not allowed")
	}
	if cfg.IP.IsUnspecified() {
		return serrors.New("ip must be set")
	}
	if cfg.CtrlPort == 0 {
		cfg.CtrlPort = DefaultCtrlPort
	}
	if cfg.EncapPort == 0 {
		cfg.EncapPort = DefaultEncapPort
	}
	if cfg.Tun == "" {
		cfg.Tun = DefaultTunName
	}
	if cfg.TunRTableId == 0 {
		cfg.TunRTableId = DefaultTunRTableId
	}
	return nil
}

func (cfg *SigConf) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(sigSample, ctx[config.ID]))
}

func (cfg *SigConf) Configure(dst io.Writer) {
	fmt.Println("Configuring settings specific to the SIG:")
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Provide SIG ID:")
		sigID, err := reader.ReadString('\n')
		sigID = strings.TrimSpace(sigID)
		if err == nil && len(sigID) > 0 {
			cfg.ID = sigID
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid SIG ID. Provide an non-empty identifier string.")
	}
	for {
		fmt.Println("Provide local ISD-AS identifier:")
		isdAS, _ := reader.ReadString('\n')
		isdAS = strings.TrimSpace(isdAS)
		ia, err := addr.IAFromString(isdAS)
		if err == nil {
			cfg.IA = ia
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid ISD-AS identifier. Provide valid ISD-AS identifier.")
	}
	defaultSigConfig := fmt.Sprintf("/etc/scion/gen/ISD%s/AS%s/sig%s-1/%s.json",
		cfg.IA.I, cfg.IA.FileFmt(false), cfg.IA.FileFmt(false), cfg.ID)
	for {
		fmt.Printf("Provide sig_config SIG traffic rule configuration file " +
			"path (default=%s):\n", defaultSigConfig)
		sigConfig, _ := reader.ReadString('\n')
		sigConfig = strings.TrimSpace(sigConfig)
		if sigConfig == "" {
			cfg.SIGConfig = defaultSigConfig
			break
		}
		if filepath.IsAbs(sigConfig) {
			cfg.SIGConfig = sigConfig
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid sig_config. " +
			"Provide absolute path to the traffic rule configuration file.")
	}
	for {
		fmt.Println("Provide the SIG bind IP address:")
		ip, _ := reader.ReadString('\n')
		ip = strings.TrimSpace(ip)
		bindIp := net.ParseIP(ip)
		if bindIp != nil {
			cfg.IP = bindIp
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid IP. Provide valid IP address.")
	}
	for {
		fmt.Printf("Provide the SIG control port (optional, default=%d):\n", DefaultCtrlPort)
		controlPort, _ := reader.ReadString('\n')
		controlPort = strings.TrimSpace(controlPort)
		if controlPort == "" {
			cfg.CtrlPort = DefaultCtrlPort
			break
		}
		ctrPort, err := strconv.Atoi(controlPort)
		if err == nil {
			cfg.CtrlPort = uint16(ctrPort)
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid control port. Provide valid control port.")
	}
	for {
		fmt.Printf("Provide the SIG encapsulation port (optional, default=%d):\n", DefaultEncapPort)
		encapsulationPort, _ := reader.ReadString('\n')
		encapsulationPort = strings.TrimSpace(encapsulationPort)
		if encapsulationPort == "" {
			cfg.EncapPort = DefaultEncapPort
			break
		}
		encapPort, err := strconv.Atoi(encapsulationPort)
		if err == nil {
			cfg.EncapPort = uint16(encapPort)
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid encapsulation port. Provide valid encapsulation port.")
	}
	for {
		fmt.Printf("Provide the name for the SIG TUN device (optional, default=%s):\n", DefaultTunName)
		tunName, err := reader.ReadString('\n')
		tunName = strings.TrimSpace(tunName)
		if tunName == "" {
			cfg.Tun = DefaultTunName
			break
		}
		if err == nil && len(tunName) > 0 {
			cfg.Tun = tunName
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid TUN device name. Provide valid TUN device name.")
	}
	for {
		fmt.Printf("Provide the ID of the SIG routing table (optional, default=%d):\n", DefaultTunRTableId)
		tunTableID, err := reader.ReadString('\n')
		tunTableID = strings.TrimSpace(tunTableID)
		if tunTableID == "" {
			cfg.TunRTableId = DefaultTunRTableId
			break
		}
		tunRTableId, err := strconv.Atoi(tunTableID)
		if err == nil {
			cfg.TunRTableId = tunRTableId
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid routing table ID. Provide valid SIG routing table ID.")
	}
	for {
		fmt.Printf("Provide the IPv4 source address hint (optional, default=):\n")
		ip4, _ := reader.ReadString('\n')
		ip4 = strings.TrimSpace(ip4)
		if ip4 == "" {
			break
		}
		srcIP4 := net.ParseIP(ip4)
		if srcIP4 != nil {
			cfg.SrcIP4 = srcIP4
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid IPv4 source address hint. Provide valid " +
			"IPv4 source address hint or leave empty.")
	}
	for {
		fmt.Printf("Provide the IPv6 source address hint (optional, default=):\n")
		ip6, _ := reader.ReadString('\n')
		ip6 = strings.TrimSpace(ip6)
		if ip6 == "" {
			break
		}
		srcIP6 := net.ParseIP(ip6)
		if srcIP6 != nil {
			cfg.SrcIP4 = srcIP6
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid IPv6 source address hint. Provide valid " +
			"IPv6 source address hint or leave empty.")
	}
	for {
		fmt.Printf("Provide the overlay address (e.g. \":30041\") " +
			"to bypass the SCION dispatcher (optional, default=):\n")
		dispatcherBypass, err := reader.ReadString('\n')
		dispatcherBypass = strings.TrimSpace(dispatcherBypass)
		if dispatcherBypass == "" {
			break
		}
		if err == nil && len(dispatcherBypass) > 0 {
			cfg.DispatcherBypass = dispatcherBypass
			break
		}
		fmt.Fprintln(os.Stderr, "ERROR: Invalid TUN device name. Provide valid TUN device name.")
	}
	return
}

func (cfg *SigConf) ConfigName() string {
	return "sig"
}
