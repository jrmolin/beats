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

package cpu

import (
	"errors"
	"fmt"
	"strings"

	"github.com/elastic/beats/v7/libbeat/common/cfgwarn"
	"github.com/elastic/elastic-agent-libs/logp"
	metrics "github.com/elastic/elastic-agent-system-metrics/metric/cpu"
)

// CPU metric types.
const (
	percentages           = "percentages"
	normalizedPercentages = "normalized_percentages"
	ticks                 = "ticks"
)

// Config for the system cpu metricset.
type Config struct {
	Metrics                 []string `config:"cpu.metrics"`
	CPUTicks                *bool    `config:"cpu_ticks"` // Deprecated.
	UserPerformanceCounters bool     `config:"use_performance_counters"`
}

// Validate validates the cpu config.
func (c Config) Validate() (metrics.MetricOpts, error) {
	opts := metrics.MetricOpts{}

	if len(c.Metrics) == 0 {
		return opts, errors.New("cpu.metrics cannot be empty")
	}

	for _, metric := range c.Metrics {
		switch strings.ToLower(metric) {
		case percentages:
			opts.Percentages = true
		case normalizedPercentages:
			opts.NormalizedPercentages = true
		case ticks:
			opts.Ticks = true
		default:
			return opts, fmt.Errorf("invalid cpu.metrics value '%v' (valid "+
				"options are %v, %v, and %v)", metric, percentages,
				normalizedPercentages, ticks)
		}
	}

	return opts, nil
}

// log warning for unsupported config
func (c Config) checkUnsupportedConfig(logger *logp.Logger) {
	if c.CPUTicks != nil {
		logger.Warn(cfgwarn.Deprecate("6.1.0", "cpu_ticks is deprecated. Add 'ticks' to the cpu.metrics list."))
	}

}

var defaultConfig = Config{
	Metrics:                 []string{percentages, normalizedPercentages},
	UserPerformanceCounters: false,
}
