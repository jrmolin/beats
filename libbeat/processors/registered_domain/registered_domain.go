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

package registered_domain

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common/cfgwarn"
	"github.com/elastic/beats/v7/libbeat/processors"
	jsprocessor "github.com/elastic/beats/v7/libbeat/processors/script/javascript/module/processor/registry"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

const (
	procName = "registered_domain"
	logName  = "processor." + procName
)

func init() {
	processors.RegisterPlugin(procName, New)
	jsprocessor.RegisterPlugin("RegisteredDomain", New)
}

type processor struct {
	config
	log *logp.Logger
}

// New constructs a new processor built from ucfg config.
func New(cfg *conf.C, log *logp.Logger) (beat.Processor, error) {
	c := defaultConfig()
	if err := cfg.Unpack(&c); err != nil {
		return nil, fmt.Errorf("fail to unpack the %v processor configuration: %w", procName, err)
	}

	return newRegisteredDomain(c, log)
}

func newRegisteredDomain(c config, logger *logp.Logger) (*processor, error) {
	log := logger.Named(logName)
	logger.Warn(cfgwarn.Beta("The " + procName + " processor is beta."))

	if c.ID != "" {
		log = log.With("instance_id", c.ID)
	}

	return &processor{config: c, log: log}, nil
}

func (p *processor) String() string {
	json, _ := json.Marshal(p.config)
	return procName + "=" + string(json)
}

func (p *processor) Run(event *beat.Event) (*beat.Event, error) {
	v, err := event.GetValue(p.Field)
	if err != nil {
		if p.IgnoreMissing || p.IgnoreFailure {
			return event, nil
		}
		return event, fmt.Errorf("registered_domain source field [%v] not found: %w", p.Field, err)
	}

	domain, ok := v.(string)
	if !ok {
		if p.IgnoreFailure {
			return event, nil
		}
		return event, fmt.Errorf("registered_domain source field [%v] is not a string", p.Field)
	}

	rd, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		if p.IgnoreFailure {
			return event, nil
		}
		return event, fmt.Errorf("failed to determine the registered domain: %w", err)
	}

	_, err = event.PutValue(p.TargetField, rd)
	if err != nil {
		if p.IgnoreFailure {
			return event, nil
		}
		return event, fmt.Errorf("failed to write registered domain to target field [%v]: %w", p.TargetField, err)
	}

	if p.TargetETLDField != "" {
		tld, _ := publicsuffix.PublicSuffix(domain)
		if tld != "" {
			if _, err = event.PutValue(p.TargetETLDField, tld); err != nil && !p.IgnoreFailure {
				return event, fmt.Errorf("failed to write effective top-level domain to target field [%v]: %w", p.TargetETLDField, err)
			}
		}
	}

	if p.TargetSubdomainField != "" {
		subdomain := strings.TrimSuffix(strings.TrimSuffix(domain, rd), ".")
		if subdomain != "" {
			_, err = event.PutValue(p.TargetSubdomainField, subdomain)
			if err != nil {
				if p.IgnoreFailure {
					return event, nil
				}
				return event, fmt.Errorf("failed to write subdomain to target field [%v]: %w", p.TargetSubdomainField, err)
			}
		}
	}

	return event, nil
}
