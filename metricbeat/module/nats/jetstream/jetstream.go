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

package jetstream

import (
	"fmt"

	"github.com/elastic/beats/v7/libbeat/common/cfgwarn"
	"github.com/elastic/beats/v7/metricbeat/helper"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/metricbeat/mb/parse"
	"github.com/elastic/elastic-agent-libs/logp"
)

const (
	defaultScheme = "http"
	// Ref: https://docs.nats.io/running-a-nats-service/nats_admin/monitoring#jetstream-information-jsz
	defaultPath        = "/jsz"
	statsCategory      = "stats"
	accountCategory    = "account"
	streamCategory     = "stream"
	consumerCategory   = "consumer"
	defaultQueryParams = "config=true&consumers=true"
)

var (
	hostParser = parse.URLHostParserBuilder{
		DefaultScheme: defaultScheme,
		DefaultPath:   defaultPath,
		QueryParams:   defaultQueryParams,
	}.Build()
)

// init registers the MetricSet with the central registry as soon as the program
// starts. The New function will be called later to instantiate an instance of
// the MetricSet for each host is defined in the module's configuration. After the
// MetricSet has been created then Fetch will begin to be called periodically.
func init() {
	mb.Registry.MustAddMetricSet("nats", "jetstream", New,
		mb.WithHostParser(hostParser),
	)
}

// MetricSet holds any configuration or state information. It must implement
// the mb.MetricSet interface. And this is best achieved by embedding
// mb.BaseMetricSet because it implements all of the required mb.MetricSet
// interface methods except for Fetch.
type MetricSet struct {
	mb.BaseMetricSet
	http   *helper.HTTP
	Log    *logp.Logger
	Config MetricsetConfig
}

// New creates a new instance of the MetricSet. New is responsible for unpacking
// any MetricSet specific configuration options if there are any.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	base.Logger().Warn(cfgwarn.Beta(fmt.Sprintf("The nats %s metricset is beta.", base.Name())))

	var config ModuleConfig
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}

	http, err := helper.NewHTTP(base)
	if err != nil {
		return nil, err
	}

	return &MetricSet{
		BaseMetricSet: base,
		http:          http,
		Log:           base.Logger().Named("nats"),
		Config:        config.Jetstream,
	}, nil
}

// Fetch method implements the data gathering and data conversion to the right
// format. It publishes the event which is then forwarded to the output. In case
// of an error set the Error field of mb.Event or simply call report.Error().
func (m *MetricSet) Fetch(report mb.ReporterV2) error {
	content, err := m.http.FetchContent()
	if err != nil {
		return fmt.Errorf("failed to fetch content for NATS JetStream: %w", err)
	}
	err = eventMapping(m, report, content)
	if err != nil {
		return fmt.Errorf("error in mapping NATS JetStream response: %w", err)
	}

	return nil
}
