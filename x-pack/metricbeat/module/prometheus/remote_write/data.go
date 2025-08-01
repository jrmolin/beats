// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package remote_write

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/model"

	"github.com/elastic/beats/v7/libbeat/common/cfgwarn"
	p "github.com/elastic/beats/v7/metricbeat/helper/prometheus"
	"github.com/elastic/beats/v7/metricbeat/mb"
	rw "github.com/elastic/beats/v7/metricbeat/module/prometheus/remote_write"
	"github.com/elastic/beats/v7/x-pack/metricbeat/module/prometheus/collector"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	counterType   = "counter_type"
	histogramType = "histogram_type"
	otherType     = "other_type"
)

type histogram struct {
	timestamp  time.Time
	buckets    []*p.Bucket
	labels     mapstr.M
	metricName string
}

func remoteWriteEventsGeneratorFactory(base mb.BaseMetricSet, opts ...rw.RemoteWriteEventsGeneratorOption) (rw.RemoteWriteEventsGenerator, error) {
	config := defaultConfig
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}

	if config.UseTypes {
		base.Logger().Named("prometheus.remote_write.cache").Debugf("Period for counter cache for remote_write: %v", config.Period.String())
		// use a counter cache with a timeout of 5x the period, as a safe value
		// to make sure that all counters are available between fetches
		counters := collector.NewCounterCache(config.Period * 5)

		g := remoteWriteTypedGenerator{
			counterCache: counters,
			rateCounters: config.RateCounters,
			metricsCount: config.MetricsCount,
			logger:       base.Logger(),
		}

		var err error
		g.counterPatterns, err = p.CompilePatternList(config.TypesPatterns.CounterPatterns)
		if err != nil {
			return nil, fmt.Errorf("unable to compile counter patterns: %w", err)
		}
		g.histogramPatterns, err = p.CompilePatternList(config.TypesPatterns.HistogramPatterns)
		if err != nil {
			return nil, fmt.Errorf("unable to compile histogram patterns: %w", err)
		}

		return &g, nil
	}

	return rw.DefaultRemoteWriteEventsGeneratorFactory(base, opts...)
}

type remoteWriteTypedGenerator struct {
	metricsCount      bool
	counterCache      collector.CounterCache
	rateCounters      bool
	counterPatterns   []*regexp.Regexp
	histogramPatterns []*regexp.Regexp
	logger            *logp.Logger
}

func (g *remoteWriteTypedGenerator) Start() {
	g.logger.Warn(cfgwarn.Beta("Prometheus 'use_types' setting is beta"))

	if g.rateCounters {
		g.logger.Warn(cfgwarn.Experimental("Prometheus 'rate_counters' setting is experimental"))
	}

	g.counterCache.Start()
}

func (g *remoteWriteTypedGenerator) Stop() {
	g.logger.Debugf("prometheus.remote_write.cache", "stopping counterCache")
	g.counterCache.Stop()
}

// GenerateEvents receives a list of Sample and:
// 1. guess the type of the sample metric
// 2. handle it properly using "types" logic
// 3. if metrics of histogram type then it is converted to ES histogram
// 4. metrics with the same set of labels are grouped into same events
func (g remoteWriteTypedGenerator) GenerateEvents(metrics model.Samples) map[string]mb.Event {
	var data mapstr.M
	histograms := map[string]histogram{}
	eventList := map[string]mb.Event{}

	for _, metric := range metrics {
		if metric == nil {
			continue
		}

		labels := mapstr.M{}
		val := float64(metric.Value)
		if math.IsNaN(val) || math.IsInf(val, 0) {
			continue
		}

		name := string(metric.Metric["__name__"])
		delete(metric.Metric, "__name__")

		for k, v := range metric.Metric {
			labels[string(k)] = v
		}

		promType := g.findMetricType(name, labels)

		labelsHash := labels.String() + metric.Timestamp.Time().String()
		labelsClone := labels.Clone()
		_ = labelsClone.Delete("le")
		if promType == histogramType {
			labelsHash = labelsClone.String() + metric.Timestamp.Time().String()
		}
		// join metrics with same labels in a single event
		if _, ok := eventList[labelsHash]; !ok {
			eventList[labelsHash] = mb.Event{
				RootFields:   mapstr.M{},
				ModuleFields: mapstr.M{},
				Timestamp:    metric.Timestamp.Time(),
			}

			// Add labels
			if len(labels) > 0 {
				if promType == histogramType {
					eventList[labelsHash].ModuleFields["labels"] = labelsClone
				} else {
					eventList[labelsHash].ModuleFields["labels"] = labels
				}
			}
		}

		e := eventList[labelsHash]

		switch promType {
		case counterType:
			data = mapstr.M{
				name: g.rateCounterFloat64(name, labels, val),
			}
		case otherType:
			data = mapstr.M{
				name: mapstr.M{
					"value": val,
				},
			}
		case histogramType:
			histKey := name + labelsClone.String()

			le, _ := labels.GetValue("le")
			upperBound := string(le.(model.LabelValue))

			bucket, err := strconv.ParseFloat(upperBound, 64)
			if err != nil {
				continue
			}
			b := &p.Bucket{
				CumulativeCount: &val,
				UpperBound:      &bucket,
			}
			hist, ok := histograms[histKey]
			if !ok {
				hist = histogram{}
			}
			hist.buckets = append(hist.buckets, b)
			hist.timestamp = metric.Timestamp.Time()
			hist.labels = labelsClone
			hist.metricName = name
			histograms[histKey] = hist
			continue
		}

		e.ModuleFields.Update(data)
	}

	// process histograms together
	g.processPromHistograms(eventList, histograms)

	if g.metricsCount {
		for _, e := range eventList {
			// In x-pack prometheus module, the metrics are nested under the "prometheus" key directly.
			// whereas in non-x-pack prometheus module, the metrics are nested under the "prometheus.metrics" key.
			// Also, it is important that we do not just increment by 1 for each e.ModuleFields["metrics"] may have more than 1 metric.
			// As, metrics are nested under the "prometheus" key, labels is also nested under the "prometheus" key. So, we need to make sure
			// we subtract 1 in case the e.ModuleFields["labels"] also exists.
			//
			// See unit tests for the same.
			if _, hasLabels := e.ModuleFields["labels"]; hasLabels {
				e.RootFields["metrics_count"] = len(e.ModuleFields) - 1
			} else {
				e.RootFields["metrics_count"] = len(e.ModuleFields)
			}
		}
	}

	return eventList
}

// rateCounterFloat64 fills a counter value and optionally adds the rate if rate_counters is enabled
func (g *remoteWriteTypedGenerator) rateCounterFloat64(name string, labels mapstr.M, value float64) mapstr.M {
	d := mapstr.M{
		"counter": value,
	}
	if g.rateCounters {
		d["rate"], _ = g.counterCache.RateFloat64(name+labels.String(), value)
	}

	return d
}

// processPromHistograms receives a group of Histograms and converts each one to ES histogram
func (g *remoteWriteTypedGenerator) processPromHistograms(eventList map[string]mb.Event, histograms map[string]histogram) {
	for _, histogram := range histograms {
		labelsHash := histogram.labels.String() + histogram.timestamp.String()
		if _, ok := eventList[labelsHash]; !ok {
			eventList[labelsHash] = mb.Event{
				ModuleFields: mapstr.M{},
				Timestamp:    histogram.timestamp,
			}

			// Add labels
			if len(histogram.labels) > 0 {
				eventList[labelsHash].ModuleFields["labels"] = histogram.labels
			}
		}

		e := eventList[labelsHash]

		hist := p.Histogram{
			Bucket: histogram.buckets,
		}
		name := strings.TrimSuffix(histogram.metricName, "_bucket")
		_ = name // skip noisy linter
		data := mapstr.M{
			name: mapstr.M{
				"histogram": collector.PromHistogramToES(g.counterCache, histogram.metricName, histogram.labels, &hist),
			},
		}
		e.ModuleFields.Update(data)
	}
}

// findMetricType evaluates the type of the metric by check the metricname format in order to handle it properly
func (g *remoteWriteTypedGenerator) findMetricType(metricName string, labels mapstr.M) string {
	leLabel := false
	if _, ok := labels["le"]; ok {
		leLabel = true
	}

	// handle user provided patterns
	if len(g.counterPatterns) > 0 {
		if p.MatchMetricFamily(metricName, g.counterPatterns) {
			return counterType
		}
	}
	if len(g.histogramPatterns) > 0 {
		if p.MatchMetricFamily(metricName, g.histogramPatterns) && leLabel {
			return histogramType
		}
	}

	// handle defaults
	if strings.HasSuffix(metricName, "_total") || strings.HasSuffix(metricName, "_sum") ||
		strings.HasSuffix(metricName, "_count") {
		return counterType
	} else if strings.HasSuffix(metricName, "_bucket") && leLabel {
		return histogramType
	}

	return otherType
}
