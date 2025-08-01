// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package sysinit

import (
	"flag"
	"fmt"
	"sync"

	"github.com/elastic/beats/v7/libbeat/common/cfgwarn"
	"github.com/elastic/beats/v7/libbeat/common/fleetmode"
	"github.com/elastic/beats/v7/metricbeat/mb"
)

var hostfsCLI = flag.String("system.hostfs", "", "Mount point of the host's filesystem for use in monitoring a host from within a container")

var once sync.Once

// A wrapper library that allows us to deal with the more complex HostFS setter logic required for legacy metricbeat code.
// This will serve as a generic init function for either the system or linux module.

// HostFSConfig is a bare struct for unpacking the config we get from agent or metricbeat
type HostFSConfig struct {
	HostFS string `config:"hostfs"`
}

// MetricbeatHostFSConfig carries config information for the hostfs setting
type MetricbeatHostFSConfig struct {
	HostFS string `config:"system.hostfs"`
}

// InitSystemModule initializes either either the system or linux module. This will produce different modules depending on if we're running under agent or not.
func InitSystemModule(base mb.BaseModule) (mb.Module, error) {
	// common code for the base use case of `hostfs` being set at the module-level
	logger := base.Logger
	hostfs, userSet, err := findConfigValue(base)
	if err != nil {
		return nil, fmt.Errorf("error fetching config value: %w", err)
	}
	if fleetmode.Enabled() {
		logger.Infof("initializing HostFS values under agent: %s", hostfs)
		return fleetInit(base, hostfs, userSet)
	}
	return metricbeatInit(base, hostfs)
}

func fleetInit(base mb.BaseModule, modulepath string, moduleSet bool) (mb.Module, error) {
	once.Do(func() {
		InitModule(modulepath, base.Logger)
	})

	// The multiple invocations here might seem buggy, but we're dealing with a case were agent's config schemea (local, per-datastream) must mesh with the global HostFS scheme used by some libraries
	// Strictly speaking, we can't guarantee that agent will send consistent HostFS config values across all datastreams, as it treats a global value as per-datastream.
	if moduleSet {
		InitModule(modulepath, base.Logger)
	}

	return &Module{BaseModule: base, HostFS: modulepath, UserSetHostFS: moduleSet}, nil
}

// Deal with the legacy configs available to metricbeat
func metricbeatInit(base mb.BaseModule, modulePath string) (mb.Module, error) {
	var hostfs = modulePath
	var userSet bool
	// allow the CLI to override other settings
	if hostfsCLI != nil && *hostfsCLI != "" {
		hostfs = *hostfsCLI
		userSet = true
	}

	once.Do(func() {
		InitModule(hostfs, base.Logger)
	})
	return &Module{BaseModule: base, HostFS: hostfs, UserSetHostFS: userSet}, nil

}

// A user can supply either `system.hostfs` or `hostfs`.
// In additon, we will probably want to change Integration Config values to `hostfs` as well.
// We need to figure out which one we got, if any.
// Returns false if no config value was set
func findConfigValue(base mb.BaseModule) (string, bool, error) {
	partialConfig := HostFSConfig{}
	err := base.UnpackConfig(&partialConfig)
	if err != nil {
		return "", false, fmt.Errorf("error unpacking hostfs config: %w", err)
	}
	// if the newer value is set, just use that.
	if partialConfig.HostFS != "" {
		return partialConfig.HostFS, true, nil
	}

	legacyConfig := MetricbeatHostFSConfig{}
	err = base.UnpackConfig(&legacyConfig)
	if err != nil {
		return "", false, fmt.Errorf("error unpacking legacy config: %w", err)
	}
	if legacyConfig.HostFS != "" {
		base.Logger.Warn(cfgwarn.Deprecate("8.0.0", "The system.hostfs config value will be removed, use `hostfs` from within the module config."))
		// Only fallback to this if the user didn't set anything else
		return legacyConfig.HostFS, true, nil
	}

	return "/", false, nil

}
