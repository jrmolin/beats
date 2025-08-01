// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package elb

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/gofrs/uuid/v5"

	"github.com/elastic/beats/v7/libbeat/autodiscover"
	"github.com/elastic/beats/v7/libbeat/autodiscover/template"
	"github.com/elastic/beats/v7/libbeat/common/cfgwarn"
	awsauto "github.com/elastic/beats/v7/x-pack/libbeat/autodiscover/providers/aws"
	awscommon "github.com/elastic/beats/v7/x-pack/libbeat/common/aws"
	"github.com/elastic/elastic-agent-autodiscover/bus"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/keystore"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func init() {
	_ = autodiscover.Registry.AddProvider("aws_elb", AutodiscoverBuilder)
}

// Provider implements autodiscover provider for aws ELBs.
type Provider struct {
	config    *awsauto.Config
	bus       bus.Bus
	appenders autodiscover.Appenders
	templates *template.Mapper
	watcher   *watcher
	uuid      uuid.UUID
}

// AutodiscoverBuilder is the main builder for this provider.
func AutodiscoverBuilder(
	beatName string,
	bus bus.Bus,
	uuid uuid.UUID,
	c *conf.C,
	keystore keystore.Keystore,
	logger *logp.Logger,
) (autodiscover.Provider, error) {
	logger.Warn(cfgwarn.Deprecate("", "aws_elb autodiscover is now deprecated and will be removed in a future release."))

	config := awsauto.DefaultConfig()
	err := c.Unpack(&config)
	if err != nil {
		return nil, err
	}

	awsCfg, err := awscommon.InitializeAWSConfig(awscommon.ConfigAWS{
		AccessKeyID:     config.AWSConfig.AccessKeyID,
		SecretAccessKey: config.AWSConfig.SecretAccessKey,
		SessionToken:    config.AWSConfig.SessionToken,
		ProfileName:     config.AWSConfig.ProfileName,
	}, logger)

	if err != nil {
		return nil, err
	}

	// Construct MetricSet with a full regions list if there is no region specified.
	if config.Regions == nil {
		svcEC2 := ec2.NewFromConfig(awsCfg, func(o *ec2.Options) {
			if config.AWSConfig.FIPSEnabled {
				o.EndpointOptions.UseFIPSEndpoint = awssdk.FIPSEndpointStateEnabled
			}

		})

		completeRegionsList, err := awsauto.GetRegions(svcEC2)
		if err != nil {
			return nil, err
		}

		config.Regions = completeRegionsList
	}

	clients := make([]autodiscoverElbClient, 0, len(config.Regions))
	for _, region := range config.Regions {
		awsCfg, err := awscommon.InitializeAWSConfig(awscommon.ConfigAWS{
			AccessKeyID:     config.AWSConfig.AccessKeyID,
			SecretAccessKey: config.AWSConfig.SecretAccessKey,
			SessionToken:    config.AWSConfig.SessionToken,
			ProfileName:     config.AWSConfig.ProfileName,
		}, logger)
		if err != nil {
			logger.Errorf("error loading AWS config for aws_elb autodiscover provider: %s", err)
		}
		awsCfg.Region = region
		clients = append(clients, elasticloadbalancingv2.NewFromConfig(awsCfg, func(o *elasticloadbalancingv2.Options) {
			if config.AWSConfig.FIPSEnabled {
				o.EndpointOptions.UseFIPSEndpoint = awssdk.FIPSEndpointStateEnabled
			}

		}))
	}

	return internalBuilder(uuid, bus, config, newAPIFetcher(clients, logger), keystore, logger)
}

// internalBuilder is mainly intended for testing via mocks and stubs.
// it can be configured to use a fetcher that doesn't actually hit the AWS API.
func internalBuilder(uuid uuid.UUID, bus bus.Bus, config *awsauto.Config, fetcher fetcher, keystore keystore.Keystore, logger *logp.Logger) (*Provider, error) {
	mapper, err := template.NewConfigMapper(config.Templates, keystore, nil, logger)
	if err != nil {
		return nil, err
	}

	p := &Provider{
		config:    config,
		bus:       bus,
		templates: &mapper,
		uuid:      uuid,
	}

	p.watcher = newWatcher(
		fetcher,
		config.Period,
		p.onWatcherStart,
		p.onWatcherStop,
	)

	return p, nil
}

// Start the autodiscover process.
func (p *Provider) Start() {
	p.watcher.start()
}

// Stop the autodiscover process.
func (p *Provider) Stop() {
	p.watcher.stop()
}

func (p *Provider) onWatcherStart(arn string, lbl *lbListener) {
	lblMap := lbl.toMap()
	e := bus.Event{
		"start":    true,
		"provider": p.uuid,
		"id":       arn,
		"host":     lblMap["host"],
		"port":     lblMap["port"],
		"aws": mapstr.M{
			"elb": lbl.toMap(),
		},
		"cloud": lbl.toCloudMap(),
		"meta": mapstr.M{
			"aws": mapstr.M{
				"elb": lbl.toMap(),
			},
			"cloud": lbl.toCloudMap(),
		},
	}

	if configs := p.templates.GetConfig(e); configs != nil {
		e["config"] = configs
	}
	p.appenders.Append(e)
	p.bus.Publish(e)
}

func (p *Provider) onWatcherStop(arn string) {
	e := bus.Event{
		"stop":     true,
		"id":       arn,
		"provider": p.uuid,
	}
	p.bus.Publish(e)
}

func (p *Provider) String() string {
	return "aws_elb"
}
