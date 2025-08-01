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

//go:build darwin || freebsd || linux || openbsd || windows || aix

package core

import (
	"fmt"
	"runtime"

	"github.com/elastic/beats/v7/libbeat/common/diagnostics"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/metricbeat/mb/parse"
	metrics "github.com/elastic/elastic-agent-system-metrics/metric/cpu"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/resolve"
)

func init() {
	mb.Registry.MustAddMetricSet("system", "core", New,
		mb.WithHostParser(parse.EmptyHostParser),
	)
}

// MetricSet for fetching system core metrics.
type MetricSet struct {
	mb.BaseMetricSet
	opts  metrics.MetricOpts
	cores *metrics.Monitor
	sys   resolve.Resolver
}

// New returns a new core MetricSet.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	config := defaultConfig
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}
	// log config related warnings
	config.checkUnsupportedConfig(base.Logger())
	opts, err := config.Validate()
	if err != nil {
		return nil, fmt.Errorf("error validating config: %w", err)
	}

	if config.CPUTicks != nil && *config.CPUTicks {
		config.Metrics = append(config.Metrics, "ticks")
	}
	sys, ok := base.Module().(resolve.Resolver)
	if !ok {
		return nil, fmt.Errorf("unexpected module type: %T", base.Module())
	}

	cpuOpts := make([]metrics.OptionFunc, 0)
	if config.UserPerformanceCounters {
		cpuOpts = append(cpuOpts, metrics.WithWindowsPerformanceCounter())
	}
	cpu, err := metrics.New(sys, cpuOpts...)
	if err != nil {
		return nil, fmt.Errorf("error initializing system.cpu metricset: %w", err)
	}

	return &MetricSet{
		BaseMetricSet: base,
		opts:          opts,
		cores:         cpu,
		sys:           sys,
	}, nil
}

// Fetch fetches CPU core metrics from the OS.
func (m *MetricSet) Fetch(report mb.ReporterV2) error {
	samples, err := m.cores.FetchCores()
	if err != nil {
		return fmt.Errorf("failed to sample CPU core times: %w", err)

	}

	for id, sample := range samples {
		event, err := sample.Format(m.opts)
		if err != nil {
			return fmt.Errorf("error formatting core data: %w", err)
		}
		event.Put("id", id)

		isOpen := report.Event(mb.Event{
			MetricSetFields: event,
		})
		if !isOpen {
			return nil
		}
	}

	return nil
}

// Diagnostics implmements the DiagnosticSet interface
func (m *MetricSet) Diagnostics() []diagnostics.DiagnosticSetup {
	m.Logger().Infof("got DiagnosticSetup request for system/core")
	if runtime.GOOS == "linux" {
		return []diagnostics.DiagnosticSetup{{
			Name:        "core-stat",
			Description: "/proc/stat file",
			Filename:    "stat",
			Callback:    m.getDiagData,
		}}
	} else {
		return nil
	}

}

func (m *MetricSet) getDiagData() []byte {
	return diagnostics.GetRawFileOrErrorString(m.sys, "/proc/stat")
}
