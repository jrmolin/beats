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

package dns

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/processors"
	jsprocessor "github.com/elastic/beats/v7/libbeat/processors/script/javascript/module/processor/registry"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/monitoring"
)

const logName = "processor.dns"

// instanceID is used to assign each instance a unique monitoring namespace.
var instanceID atomic.Uint32

func init() {
	processors.RegisterPlugin("dns", New)
	jsprocessor.RegisterPlugin("DNS", New)
}

type processor struct {
	config
	resolver resolver
	log      *logp.Logger
}

// New constructs a new DNS processor.
func New(cfg *conf.C, log *logp.Logger) (beat.Processor, error) {
	c := defaultConfig()
	if err := cfg.Unpack(&c); err != nil {
		return nil, fmt.Errorf("fail to unpack the dns configuration: %w", err)
	}

	// Logging and metrics (each processor instance has a unique ID).
	var (
		id      = int(instanceID.Add(1))
		metrics = monitoring.Default.NewRegistry(logName+"."+strconv.Itoa(id), monitoring.DoNotReport)
	)

	log = log.Named(logName).With("instance_id", id)
	log.Debugf("DNS processor config: %+v", c)
	resolver, err := newMiekgResolver(metrics, c.Timeout, c.Transport, c.Nameservers...)
	if err != nil {
		return nil, err
	}

	cache, err := newLookupCache(metrics.NewRegistry("cache"), c.cacheConfig, resolver)
	if err != nil {
		return nil, err
	}

	return &processor{config: c, resolver: cache, log: log}, nil
}

func (p *processor) Run(event *beat.Event) (*beat.Event, error) {
	var tagOnce sync.Once
	for field, target := range p.reverseFlat {
		if err := p.processField(field, target, p.Action, event); err != nil {
			p.log.Debugf("DNS processor failed: %v", err)
			tagOnce.Do(func() { _ = mapstr.AddTags(event.Fields, p.TagOnFailure) })
		}
	}
	return event, nil
}

func (p *processor) processField(source, target string, action fieldAction, event *beat.Event) error {
	v, err := event.GetValue(source)
	if err != nil {
		//nolint:nilerr // an empty source field isn't considered an error for this processor
		return nil
	}

	strVal, ok := v.(string)
	if !ok {
		return nil
	}

	result, err := p.resolver.Lookup(strVal, p.Type)
	if err != nil {
		return fmt.Errorf("dns lookup (%s) of %s value '%s' failed: %w", p.Type, source, strVal, err)
	}

	// PTR lookups return a scalar. All other lookup types return a string slice.
	if p.Type == typePTR {
		return setFieldValue(action, event, target, result.Data[0])
	}
	return setFieldSliceValue(action, event, target, result.Data)
}

func setFieldValue(action fieldAction, event *beat.Event, key, value string) error {
	switch action {
	case actionReplace:
		_, err := event.PutValue(key, value)
		return err
	case actionAppend:
		old, err := event.PutValue(key, value)
		if err != nil {
			return err
		}

		if old != nil {
			switch v := old.(type) {
			case string:
				_, err = event.PutValue(key, []string{v, value})
			case []string:
				_, err = event.PutValue(key, append(v, value))
			}
		}
		return err
	default:
		panic(fmt.Errorf("unexpected dns field action value encountered: %s", action))
	}
}

func setFieldSliceValue(action fieldAction, event *beat.Event, key string, value []string) error {
	switch action {
	case actionReplace:
		_, err := event.PutValue(key, value)
		return err
	case actionAppend:
		old, err := event.PutValue(key, value)
		if err != nil {
			return err
		}

		if old != nil {
			switch v := old.(type) {
			case string:
				_, err = event.PutValue(key, append([]string{v}, value...))
			case []string:
				_, err = event.PutValue(key, append(v, value...))
			}
		}
		return err
	default:
		panic(fmt.Errorf("unexpected dns field action value encountered: %s", action))
	}
}

func (p processor) String() string {
	return fmt.Sprintf("dns=[timeout=%v, nameservers=[%v], action=%v, type=%v, fields=[%+v]",
		p.Timeout, strings.Join(p.Nameservers, ","), p.Action, p.Type, p.reverseFlat)
}
