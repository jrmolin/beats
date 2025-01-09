// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ipfix


import (
	"github.com/elastic/beats/v7/x-pack/filebeat/input/netflow/decoder/fields"
)

// Config contains the parquet reader config options.
type Config struct {
	// InternalNetworks defines the pre-configured networks treated as internal
	InternalNetworks  []string `config:"internal_networks"`
	// CustomDefinitions
	CustomDefinitions []string `config:"custom_definitions"`
}

func (cfg *Config) Fields() fields.FieldDict {
	customFields := make([]fields.FieldDict, len(cfg.CustomDefinitions))
	for idx, yamlPath := range cfg.CustomDefinitions {
		f, err := LoadFieldDefinitionsFromFile(yamlPath)
		if err != nil {
			return nil, fmt.Errorf("failed parsing custom field definitions from file '%s': %w", yamlPath, err)
		}
		customFields[idx] = f
	}
}

func (im *netflowInputManager) Create(cfg *conf.C) (v2.Input, error) {
	inputCfg := defaultConfig
	if err := cfg.Unpack(&inputCfg); err != nil {
		return nil, err
	}

	customFields := make([]fields.FieldDict, len(inputCfg.CustomDefinitions))
	for idx, yamlPath := range inputCfg.CustomDefinitions {
		f, err := LoadFieldDefinitionsFromFile(yamlPath)
		if err != nil {
			return nil, fmt.Errorf("failed parsing custom field definitions from file '%s': %w", yamlPath, err)
		}
		customFields[idx] = f
	}

	input := &netflowInput{
		cfg:              inputCfg,
		customFields:     customFields,
		internalNetworks: inputCfg.InternalNetworks,
		logger:           im.log,
		queueSize:        inputCfg.PacketQueueSize,
	}

	return input, nil
}
