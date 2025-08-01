// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !aix

package azureeventhub

import (
	"fmt"
	"os"

	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/devigned/tab"

	v2 "github.com/elastic/beats/v7/filebeat/input/v2"
	"github.com/elastic/beats/v7/libbeat/feature"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/go-concert/unison"
)

const (
	eventHubConnector        = ";EntityPath="
	expandEventListFromField = "records"
	inputName                = "azure-eventhub"
	processorV1              = "v1"
	processorV2              = "v2"
)

var environments = map[string]azure.Environment{
	azure.ChinaCloud.ResourceManagerEndpoint:        azure.ChinaCloud,
	azure.GermanCloud.ResourceManagerEndpoint:       azure.GermanCloud,
	azure.PublicCloud.ResourceManagerEndpoint:       azure.PublicCloud,
	azure.USGovernmentCloud.ResourceManagerEndpoint: azure.USGovernmentCloud,
}

// Plugin returns the Azure Event Hub input plugin.
//
// Required register the plugin loader for the
// input API v2.
func Plugin(log *logp.Logger) v2.Plugin {
	return v2.Plugin{
		Name:       inputName,
		Stability:  feature.Stable,
		Deprecated: false,
		Info:       "Collect logs from Azure Event Hub",
		Manager: &eventHubInputManager{
			log: log,
		},

		// ExcludeFromFIPS = true to prevent this input from being used in FIPS-capable
		// Filebeat distributions. This input indirectly uses algorithms that are not
		// FIPS-compliant. Specifically, the input depends on the
		// github.com/Azure/azure-sdk-for-go/sdk/azidentity package which, in turn,
		// depends on the golang.org/x/crypto/pkcs12 package, which is not FIPS-compliant.
		ExcludeFromFIPS: true,
	}
}

// azureInputConfig is responsible for creating the right azure-eventhub input
// based on the configuration.
type eventHubInputManager struct {
	log *logp.Logger
}

// Init initializes the input manager.
func (m *eventHubInputManager) Init(unison.Group) error {
	return nil
}

// Create creates a new azure-eventhub input based on the configuration.
func (m *eventHubInputManager) Create(cfg *conf.C) (v2.Input, error) {

	// Register the logs tracer only if the environment variable is
	// set to avoid the overhead of the tracer in environments where
	// it's not needed.
	if os.Getenv("BEATS_AZURE_EVENTHUB_INPUT_TRACING_ENABLED") == "true" {
		tab.Register(&logsOnlyTracer{logger: m.log})
	}

	config := defaultConfig()
	if err := cfg.Unpack(&config); err != nil {
		return nil, fmt.Errorf("reading %s input config: %w", inputName, err)
	}

	config.checkUnsupportedParams(m.log)

	switch config.ProcessorVersion {
	case processorV1:
		return newEventHubInputV1(config, m.log)
	case processorV2:
		return newEventHubInputV2(config, m.log)
	default:
		return nil, fmt.Errorf("invalid azure-eventhub processor version: %s (available versions: v1, v2)", config.ProcessorVersion)
	}
}
