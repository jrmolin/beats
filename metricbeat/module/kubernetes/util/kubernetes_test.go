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

package util

import (
	"fmt"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/elastic/beats/v7/metricbeat/mb"

	"github.com/stretchr/testify/assert"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	kubernetes2 "github.com/elastic/beats/v7/libbeat/autodiscover/providers/kubernetes"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes/metadata"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent-libs/mapstr"

	"github.com/stretchr/testify/require"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8smetafake "k8s.io/client-go/metadata/fake"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
)

func TestWatchOptions(t *testing.T) {
	log := logptest.NewTestingLogger(t, "test")

	client := k8sfake.NewSimpleClientset()
	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
	}

	options, err := getWatchOptions(config, false, client, log)
	require.NoError(t, err)
	require.Equal(t, options.SyncTimeout, config.SyncPeriod)
	require.NotEqual(t, options.Node, config.Node)

	options, err = getWatchOptions(config, true, client, log)
	require.NoError(t, err)
	require.Equal(t, options.SyncTimeout, config.SyncPeriod)
	require.Equal(t, options.Node, config.Node)
}

func TestCreateWatcher(t *testing.T) {
	resourceWatchers := NewWatchers()
	metricsRepo := NewMetricsRepo()

	client := k8sfake.NewSimpleClientset()
	metadataClient := k8smetafake.NewSimpleMetadataClient(k8smetafake.NewTestScheme())
	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
	}
	log := logptest.NewTestingLogger(t, "test")

	options, err := getWatchOptions(config, false, client, log)
	require.NoError(t, err)

	created, err := createWatcher(
		NamespaceResource,
		&kubernetes.Node{},
		*options,
		client,
		metadataClient,
		resourceWatchers,
		metricsRepo,
		config.Namespace,
		false,
		logptest.NewTestingLogger(t, ""),
	)
	require.True(t, created)
	require.NoError(t, err)

	resourceWatchers.lock.Lock()
	require.Equal(t, 1, len(resourceWatchers.metaWatchersMap))
	require.NotNil(t, resourceWatchers.metaWatchersMap[NamespaceResource])
	require.NotNil(t, resourceWatchers.metaWatchersMap[NamespaceResource].watcher)
	resourceWatchers.lock.Unlock()

	created, err = createWatcher(
		NamespaceResource,
		&kubernetes.Namespace{},
		*options, client,
		metadataClient,
		resourceWatchers,
		metricsRepo,
		config.Namespace,
		true,
		logptest.NewTestingLogger(t, ""),
	)
	require.False(t, created)
	require.NoError(t, err)

	resourceWatchers.lock.Lock()
	require.Equal(t, 1, len(resourceWatchers.metaWatchersMap))
	require.NotNil(t, resourceWatchers.metaWatchersMap[NamespaceResource])
	require.NotNil(t, resourceWatchers.metaWatchersMap[NamespaceResource].watcher)
	resourceWatchers.lock.Unlock()

	created, err = createWatcher(
		DeploymentResource,
		&kubernetes.Deployment{},
		*options, client,
		metadataClient,
		resourceWatchers,
		metricsRepo,
		config.Namespace,
		false, logptest.NewTestingLogger(t, ""))
	require.True(t, created)
	require.NoError(t, err)

	resourceWatchers.lock.Lock()
	require.Equal(t, 2, len(resourceWatchers.metaWatchersMap))
	require.NotNil(t, resourceWatchers.metaWatchersMap[DeploymentResource])
	require.NotNil(t, resourceWatchers.metaWatchersMap[NamespaceResource])
	resourceWatchers.lock.Unlock()
}

func TestAddToMetricsetsUsing(t *testing.T) {
	resourceWatchers := NewWatchers()
	metricsRepo := NewMetricsRepo()

	client := k8sfake.NewSimpleClientset()
	metadataClient := k8smetafake.NewSimpleMetadataClient(k8smetafake.NewTestScheme())
	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
	}
	log := logptest.NewTestingLogger(t, "test")

	options, err := getWatchOptions(config, false, client, log)
	require.NoError(t, err)

	// Create the new entry with watcher and nil string array first
	created, err := createWatcher(
		DeploymentResource,
		&kubernetes.Deployment{},
		*options, client,
		metadataClient,
		resourceWatchers,
		metricsRepo,
		config.Namespace,
		false, logptest.NewTestingLogger(t, ""))
	require.True(t, created)
	require.NoError(t, err)

	resourceWatchers.lock.Lock()
	require.NotNil(t, resourceWatchers.metaWatchersMap[DeploymentResource].watcher)
	require.Equal(t, []string{}, resourceWatchers.metaWatchersMap[DeploymentResource].metricsetsUsing)
	resourceWatchers.lock.Unlock()

	metricsetDeployment := "state_deployment"
	addToMetricsetsUsing(DeploymentResource, metricsetDeployment, resourceWatchers)
	resourceWatchers.lock.Lock()
	require.Equal(t, []string{metricsetDeployment}, resourceWatchers.metaWatchersMap[DeploymentResource].metricsetsUsing)
	resourceWatchers.lock.Unlock()

	metricsetContainer := "container"
	addToMetricsetsUsing(DeploymentResource, metricsetContainer, resourceWatchers)
	resourceWatchers.lock.Lock()
	require.Equal(t, []string{metricsetDeployment, metricsetContainer}, resourceWatchers.metaWatchersMap[DeploymentResource].metricsetsUsing)
	resourceWatchers.lock.Unlock()
}

func TestRemoveFromMetricsetsUsing(t *testing.T) {
	resourceWatchers := NewWatchers()
	metricsRepo := NewMetricsRepo()

	client := k8sfake.NewSimpleClientset()
	metadataClient := k8smetafake.NewSimpleMetadataClient(k8smetafake.NewTestScheme())
	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
	}
	log := logptest.NewTestingLogger(t, "test")

	options, err := getWatchOptions(config, false, client, log)
	require.NoError(t, err)

	// Create the new entry with watcher and nil string array first
	created, err := createWatcher(
		DeploymentResource,
		&kubernetes.Deployment{},
		*options,
		client,
		metadataClient,
		resourceWatchers,
		metricsRepo,
		config.Namespace,
		false,
		logptest.NewTestingLogger(t, ""),
	)
	require.True(t, created)
	require.NoError(t, err)

	metricsetDeployment := "state_deployment"
	metricsetPod := "state_pod"
	addToMetricsetsUsing(DeploymentResource, metricsetDeployment, resourceWatchers)
	addToMetricsetsUsing(DeploymentResource, metricsetPod, resourceWatchers)

	resourceWatchers.lock.Lock()
	defer resourceWatchers.lock.Unlock()

	removed, size := removeFromMetricsetsUsing(DeploymentResource, metricsetDeployment, resourceWatchers)
	require.True(t, removed)
	require.Equal(t, 1, size)

	removed, size = removeFromMetricsetsUsing(DeploymentResource, metricsetDeployment, resourceWatchers)
	require.False(t, removed)
	require.Equal(t, 1, size)

	removed, size = removeFromMetricsetsUsing(DeploymentResource, metricsetPod, resourceWatchers)
	require.True(t, removed)
	require.Equal(t, 0, size)
}

func TestWatcherContainerMetrics(t *testing.T) {
	resourceWatchers := NewWatchers()
	metricsRepo := NewMetricsRepo()

	containerName := "test"
	cpuLimit := resource.MustParse("100m")
	memoryLimit := resource.MustParse("100Mi")
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID:  types.UID("mockuid"),
			Name: "enrich",
			Labels: map[string]string{
				"label": "value",
			},
			Namespace: "default",
		},
		Spec: v1.PodSpec{
			NodeName: "test-node",
			Containers: []v1.Container{
				{
					Name: containerName,
					Resources: v1.ResourceRequirements{
						Limits: v1.ResourceList{
							v1.ResourceCPU:    cpuLimit,
							v1.ResourceMemory: memoryLimit,
						},
					},
				},
			},
		},
	}
	podId := NewPodId(pod.Namespace, pod.Name)
	resourceWatchers.lock.Lock()

	watcher := newMockWatcher()
	metaWatcher := &metaWatcher{
		watcher:         watcher,
		started:         false,
		metricsetsUsing: []string{"pod"},
		enrichers:       make(map[string]*enricher),
		metricsRepo:     metricsRepo,
	}
	resourceWatchers.metaWatchersMap[PodResource] = metaWatcher
	addEventHandlersToWatcher(metaWatcher, resourceWatchers)
	resourceWatchers.lock.Unlock()

	// add Pod and verify container metrics are present and valid
	watcher.handler.OnAdd(pod)

	containerStore := metricsRepo.GetNodeStore(pod.Spec.NodeName).GetPodStore(podId).GetContainerStore(containerName)
	metrics := containerStore.GetContainerMetrics()
	require.NotNil(t, metrics)
	assert.Equal(t, 0.1, metrics.CoresLimit.Value)
	assert.Equal(t, 100*1024*1024.0, metrics.MemoryLimit.Value)

	// modify the limit and verify the new value is present
	pod.Spec.Containers[0].Resources.Limits[v1.ResourceCPU] = resource.MustParse("200m")
	watcher.handler.OnUpdate(pod)
	metrics = containerStore.GetContainerMetrics()
	require.NotNil(t, metrics)
	assert.Equal(t, 0.2, metrics.CoresLimit.Value)

	// delete the pod and verify no metrics are present
	watcher.handler.OnDelete(pod)
	containerStore = metricsRepo.GetNodeStore(pod.Spec.NodeName).GetPodStore(podId).GetContainerStore(containerName)
	metrics = containerStore.GetContainerMetrics()
	require.NotNil(t, metrics)
	assert.Nil(t, metrics.CoresLimit)
	assert.Nil(t, metrics.MemoryLimit)
}

func TestWatcherNodeMetrics(t *testing.T) {
	resourceWatchers := NewWatchers()
	metricsRepo := NewMetricsRepo()

	cpuLimit := resource.MustParse("100m")
	memoryLimit := resource.MustParse("100Mi")
	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			UID:  types.UID("mockuid"),
			Name: "enrich",
			Labels: map[string]string{
				"label": "value",
			},
			Namespace: "default",
		},
		Status: v1.NodeStatus{
			Capacity: v1.ResourceList{
				v1.ResourceCPU:    cpuLimit,
				v1.ResourceMemory: memoryLimit,
			},
		},
	}
	resourceWatchers.lock.Lock()

	watcher := newMockWatcher()
	metaWatcher := &metaWatcher{
		watcher:         watcher,
		started:         false,
		metricsetsUsing: []string{"pod"},
		enrichers:       make(map[string]*enricher),
		metricsRepo:     metricsRepo,
	}
	resourceWatchers.metaWatchersMap[NodeResource] = metaWatcher
	addEventHandlersToWatcher(metaWatcher, resourceWatchers)
	resourceWatchers.lock.Unlock()

	// add node and verify container metrics are present and valid
	watcher.handler.OnAdd(node)

	nodeStore := metricsRepo.GetNodeStore(node.Name)
	metrics := nodeStore.GetNodeMetrics()
	require.NotNil(t, metrics)
	assert.Equal(t, 0.1, metrics.CoresAllocatable.Value)
	assert.Equal(t, 100*1024*1024.0, metrics.MemoryAllocatable.Value)

	// modify the limit and verify the new value is present
	node.Status.Capacity[v1.ResourceCPU] = resource.MustParse("200m")
	watcher.handler.OnUpdate(node)
	metrics = nodeStore.GetNodeMetrics()
	require.NotNil(t, metrics)
	assert.Equal(t, 0.2, metrics.CoresAllocatable.Value)

	// delete the node and verify no metrics are present
	watcher.handler.OnDelete(node)
	nodeStore = metricsRepo.GetNodeStore(node.Name)
	metrics = nodeStore.GetNodeMetrics()
	require.NotNil(t, metrics)
	assert.Nil(t, metrics.CoresAllocatable)
	assert.Nil(t, metrics.MemoryAllocatable)
}

func TestCreateAllWatchers(t *testing.T) {
	resourceWatchers := NewWatchers()
	metricsRepo := NewMetricsRepo()

	client := k8sfake.NewSimpleClientset()
	metadataClient := k8smetafake.NewSimpleMetadataClient(k8smetafake.NewTestScheme())
	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
		AddResourceMetadata: &metadata.AddResourceMetadataConfig{
			CronJob:    false,
			Deployment: true,
		},
	}
	log := logptest.NewTestingLogger(t, "test")

	// Start watchers based on a resource that does not exist should cause an error
	err := createAllWatchers(
		client,
		metadataClient,
		"does-not-exist",
		"does-not-exist",
		false,
		config,
		log,
		resourceWatchers,
		metricsRepo)
	require.Error(t, err)
	resourceWatchers.lock.Lock()
	require.Equal(t, 0, len(resourceWatchers.metaWatchersMap))
	resourceWatchers.lock.Unlock()

	// Start watcher for a resource that requires other resources, should start all the watchers
	metricsetPod := "pod"
	extras := getExtraWatchers(PodResource, config.AddResourceMetadata)
	err = createAllWatchers(
		client,
		metadataClient,
		metricsetPod,
		PodResource,
		false,
		config,
		log,
		resourceWatchers,
		metricsRepo)
	require.NoError(t, err)

	// Check that all the required watchers are in the map
	resourceWatchers.lock.Lock()
	// we add 1 to the expected result to represent the resource itself
	require.Equal(t, len(extras)+1, len(resourceWatchers.metaWatchersMap))
	for _, extra := range extras {
		require.NotNil(t, resourceWatchers.metaWatchersMap[extra])
	}
	resourceWatchers.lock.Unlock()
}

func TestCreateMetaGen(t *testing.T) {
	resourceWatchers := NewWatchers()
	metricsRepo := NewMetricsRepo()

	commonMetaConfig := metadata.Config{}
	commonConfig, err := conf.NewConfigFrom(&commonMetaConfig)
	require.NoError(t, err)

	log := logptest.NewTestingLogger(t, "test")

	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
		AddResourceMetadata: &metadata.AddResourceMetadataConfig{
			CronJob:    false,
			Deployment: true,
		},
	}
	client := k8sfake.NewSimpleClientset()
	metadataClient := k8smetafake.NewSimpleMetadataClient(k8smetafake.NewTestScheme())

	_, err = createMetadataGen(client, commonConfig, config.AddResourceMetadata, DeploymentResource, resourceWatchers)
	// At this point, no watchers were created
	require.Error(t, err)

	// Create the watchers necessary for the metadata generator
	metricsetDeployment := "state_deployment"
	err = createAllWatchers(
		client,
		metadataClient,
		metricsetDeployment,
		DeploymentResource,
		false,
		config,
		log,
		resourceWatchers,
		metricsRepo)
	require.NoError(t, err)

	// Create the generators, this time without error
	_, err = createMetadataGen(client, commonConfig, config.AddResourceMetadata, DeploymentResource, resourceWatchers)
	require.NoError(t, err)
}

func TestCreateMetaGenSpecific(t *testing.T) {
	resourceWatchers := NewWatchers()
	metricsRepo := NewMetricsRepo()

	commonMetaConfig := metadata.Config{}
	commonConfig, err := conf.NewConfigFrom(&commonMetaConfig)
	require.NoError(t, err)

	log := logptest.NewTestingLogger(t, "test")

	namespaceConfig, err := conf.NewConfigFrom(map[string]interface{}{
		"enabled": true,
	})
	require.NoError(t, err)

	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
		AddResourceMetadata: &metadata.AddResourceMetadataConfig{
			CronJob:    false,
			Deployment: true,
			Namespace:  namespaceConfig,
		},
	}
	client := k8sfake.NewSimpleClientset()
	metadataClient := k8smetafake.NewSimpleMetadataClient(k8smetafake.NewTestScheme())

	// For pod:
	metricsetPod := "pod"

	_, err = createMetadataGenSpecific(client, commonConfig, config.AddResourceMetadata, PodResource, resourceWatchers)
	// At this point, no watchers were created
	require.Error(t, err)

	// Create the pod resource + the extras
	err = createAllWatchers(
		client,
		metadataClient,
		metricsetPod,
		PodResource,
		false,
		config,
		log,
		resourceWatchers,
		metricsRepo)
	require.NoError(t, err)

	_, err = createMetadataGenSpecific(client, commonConfig, config.AddResourceMetadata, PodResource, resourceWatchers)
	require.NoError(t, err)

	// For service:
	_, err = createMetadataGenSpecific(client, commonConfig, config.AddResourceMetadata, ServiceResource, resourceWatchers)
	// At this point, no watchers were created
	require.Error(t, err)

	// Create the service resource + the extras
	metricsetService := "state_service"
	err = createAllWatchers(
		client,
		metadataClient,
		metricsetService,
		ServiceResource,
		false,
		config,
		log,
		resourceWatchers,
		metricsRepo)
	require.NoError(t, err)

	_, err = createMetadataGenSpecific(client, commonConfig, config.AddResourceMetadata, ServiceResource, resourceWatchers)
	require.NoError(t, err)
}

func TestBuildMetadataEnricher_Start_Stop(t *testing.T) {
	resourceWatchers := NewWatchers()

	metricsetNamespace := "state_namespace"
	metricsetDeployment := "state_deployment"

	resourceWatchers.lock.Lock()
	resourceWatchers.metaWatchersMap[NamespaceResource] = &metaWatcher{
		watcher:         &mockWatcher{},
		started:         false,
		metricsetsUsing: []string{metricsetNamespace, metricsetDeployment},
		enrichers:       make(map[string]*enricher),
	}
	resourceWatchers.metaWatchersMap[DeploymentResource] = &metaWatcher{
		watcher:         &mockWatcher{},
		started:         true,
		metricsetsUsing: []string{metricsetDeployment},
		enrichers:       make(map[string]*enricher),
	}
	resourceWatchers.lock.Unlock()

	funcs := mockFuncs{}
	namespaceConfig, err := conf.NewConfigFrom(map[string]interface{}{
		"enabled": true,
	})
	require.NoError(t, err)
	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
		AddResourceMetadata: &metadata.AddResourceMetadataConfig{
			CronJob:    false,
			Deployment: false,
			Namespace:  namespaceConfig,
		},
	}

	log := logptest.NewTestingLogger(t, selector)

	enricherNamespace := buildMetadataEnricher(
		metricsetNamespace,
		NamespaceResource,
		resourceWatchers,
		config,
		funcs.update,
		funcs.delete,
		funcs.index,
		log,
	)
	resourceWatchers.lock.Lock()
	watcher := resourceWatchers.metaWatchersMap[NamespaceResource]
	require.False(t, watcher.started)
	resourceWatchers.lock.Unlock()

	enricherNamespace.Start(resourceWatchers)
	resourceWatchers.lock.Lock()
	watcher = resourceWatchers.metaWatchersMap[NamespaceResource]
	require.True(t, watcher.started)
	resourceWatchers.lock.Unlock()

	// Stopping should not stop the watcher because it is still being used by deployment metricset
	enricherNamespace.Stop(resourceWatchers)
	resourceWatchers.lock.Lock()
	watcher = resourceWatchers.metaWatchersMap[NamespaceResource]
	require.True(t, watcher.started)
	require.Equal(t, []string{metricsetDeployment}, watcher.metricsetsUsing)
	resourceWatchers.lock.Unlock()

	// Stopping the deployment watcher should stop now both watchers
	enricherDeployment := buildMetadataEnricher(
		metricsetDeployment,
		DeploymentResource,
		resourceWatchers,
		config,
		funcs.update,
		funcs.delete,
		funcs.index,
		log,
	)
	enricherDeployment.Stop(resourceWatchers)

	resourceWatchers.lock.Lock()
	watcher = resourceWatchers.metaWatchersMap[NamespaceResource]

	require.False(t, watcher.started)
	require.Equal(t, []string{}, watcher.metricsetsUsing)

	watcher = resourceWatchers.metaWatchersMap[DeploymentResource]
	require.False(t, watcher.started)
	require.Equal(t, []string{}, watcher.metricsetsUsing)

	resourceWatchers.lock.Unlock()
}

func TestBuildMetadataEnricher_Start_Stop_SameResources(t *testing.T) {
	resourceWatchers := NewWatchers()

	metricsetPod := "pod"
	metricsetStatePod := "state_pod"

	resourceWatchers.lock.Lock()
	resourceWatchers.metaWatchersMap[PodResource] = &metaWatcher{
		watcher:         &mockWatcher{},
		started:         false,
		metricsetsUsing: []string{metricsetStatePod, metricsetPod},
		enrichers:       make(map[string]*enricher),
	}
	resourceWatchers.lock.Unlock()

	funcs := mockFuncs{}
	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
		AddResourceMetadata: &metadata.AddResourceMetadataConfig{
			CronJob:    false,
			Deployment: false,
		},
	}

	log := logptest.NewTestingLogger(t, selector)
	enricherPod := buildMetadataEnricher(metricsetPod, PodResource, resourceWatchers, config,
		funcs.update, funcs.delete, funcs.index, log)
	resourceWatchers.lock.Lock()
	watcher := resourceWatchers.metaWatchersMap[PodResource]
	require.False(t, watcher.started)
	resourceWatchers.lock.Unlock()

	enricherPod.Start(resourceWatchers)
	resourceWatchers.lock.Lock()
	watcher = resourceWatchers.metaWatchersMap[PodResource]
	require.True(t, watcher.started)
	resourceWatchers.lock.Unlock()

	// Stopping should not stop the watcher because it is still being used by state_pod metricset
	enricherPod.Stop(resourceWatchers)
	resourceWatchers.lock.Lock()
	watcher = resourceWatchers.metaWatchersMap[PodResource]
	require.True(t, watcher.started)
	require.Equal(t, []string{metricsetStatePod}, watcher.metricsetsUsing)
	resourceWatchers.lock.Unlock()

	// Stopping the state_pod watcher should stop pod watcher
	enricherStatePod := buildMetadataEnricher(metricsetStatePod, PodResource, resourceWatchers, config,
		funcs.update, funcs.delete, funcs.index, log)
	enricherStatePod.Stop(resourceWatchers)

	resourceWatchers.lock.Lock()
	watcher = resourceWatchers.metaWatchersMap[PodResource]
	require.False(t, watcher.started)
	require.Equal(t, []string{}, watcher.metricsetsUsing)
	resourceWatchers.lock.Unlock()
}

func TestBuildMetadataEnricher_EventHandler(t *testing.T) {
	resourceWatchers := NewWatchers()
	metricsRepo := NewMetricsRepo()

	resourceWatchers.lock.Lock()
	watcher := &metaWatcher{
		watcher:         newMockWatcher(),
		started:         false,
		metricsetsUsing: []string{"pod"},
		enrichers:       make(map[string]*enricher),
		metricsRepo:     metricsRepo,
	}
	resourceWatchers.metaWatchersMap[PodResource] = watcher
	addEventHandlersToWatcher(watcher, resourceWatchers)
	resourceWatchers.lock.Unlock()

	funcs := mockFuncs{}
	resource := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID:  types.UID("mockuid"),
			Name: "enrich",
			Labels: map[string]string{
				"label": "value",
			},
			Namespace: "default",
		},
	}
	events := []mapstr.M{
		{"name": "unknown"},
		{"name": "enrich"},
	}

	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
		AddResourceMetadata: &metadata.AddResourceMetadataConfig{
			CronJob:    false,
			Deployment: false,
		},
	}

	metricset := "pod"
	log := logptest.NewTestingLogger(t, selector)

	enricher := buildMetadataEnricher(metricset, PodResource, resourceWatchers, config,
		funcs.update, funcs.delete, funcs.index, log)
	resourceWatchers.lock.Lock()
	wData := resourceWatchers.metaWatchersMap[PodResource]
	mockW, ok := wData.watcher.(*mockWatcher)
	require.True(t, ok)
	require.NotNil(t, mockW.handler)
	resourceWatchers.lock.Unlock()

	enricher.Start(resourceWatchers)
	resourceWatchers.lock.Lock()
	require.True(t, watcher.started)
	resourceWatchers.lock.Unlock()

	mockW.handler.OnAdd(resource)
	err := mockW.Store().Add(resource)
	require.NoError(t, err)

	// Test enricher

	enricher.Enrich(events)

	require.Equal(t, []mapstr.M{
		{"name": "unknown"},
		{
			"name":    "enrich",
			"_module": mapstr.M{"label": "value", "pod": mapstr.M{"name": "enrich", "uid": "mockuid"}},
			"meta":    mapstr.M{"orchestrator": mapstr.M{"cluster": mapstr.M{"name": "gke-4242"}}},
		},
	}, events)

	require.Equal(t, resource, funcs.updated)

	// Enrich a pod (metadata goes in root level)
	events = []mapstr.M{
		{"name": "unknown"},
		{"name": "enrich"},
	}
	enricher.isPod = true
	enricher.Enrich(events)

	require.Equal(t, []mapstr.M{
		{"name": "unknown"},
		{
			"name":    "enrich",
			"uid":     "mockuid",
			"_module": mapstr.M{"label": "value"},
			"meta":    mapstr.M{"orchestrator": mapstr.M{"cluster": mapstr.M{"name": "gke-4242"}}},
		},
	}, events)

	// Emit delete event
	resourceWatchers.lock.Lock()
	wData = resourceWatchers.metaWatchersMap[PodResource]
	mockW, ok = wData.watcher.(*mockWatcher)
	require.True(t, ok)
	resourceWatchers.lock.Unlock()

	mockW.handler.OnDelete(resource)
	err = mockW.Store().Delete(resource)
	require.NoError(t, err)

	require.Equal(t, resource, funcs.deleted)

	events = []mapstr.M{
		{"name": "unknown"},
		{"name": "enrich"},
	}
	enricher.Enrich(events)

	require.Equal(t, []mapstr.M{
		{"name": "unknown"},
		{"name": "enrich"},
	}, events)

	enricher.Stop(resourceWatchers)
	resourceWatchers.lock.Lock()
	watcher = resourceWatchers.metaWatchersMap[PodResource]
	require.False(t, watcher.started)
	resourceWatchers.lock.Unlock()
}

func TestBuildMetadataEnricher_PartialMetadata(t *testing.T) {
	resourceWatchers := NewWatchers()
	metricsRepo := NewMetricsRepo()

	resourceWatchers.lock.Lock()
	watcher := &metaWatcher{
		watcher: &mockWatcher{
			store: cache.NewStore(cache.MetaNamespaceKeyFunc),
		},
		started:         false,
		metricsetsUsing: []string{"replicaset"},
		enrichers:       make(map[string]*enricher),
		metricsRepo:     metricsRepo,
	}
	resourceWatchers.metaWatchersMap[ReplicaSetResource] = watcher
	addEventHandlersToWatcher(watcher, resourceWatchers)
	resourceWatchers.lock.Unlock()

	isController := true
	resource := &metav1.PartialObjectMetadata{
		ObjectMeta: metav1.ObjectMeta{
			UID:  types.UID("mockuid"),
			Name: "enrich",
			Labels: map[string]string{
				"label": "value",
			},
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
					Name:       "enrich_deployment",
					Controller: &isController,
				},
			},
		},
	}

	config := &kubernetesConfig{
		Namespace:  "test-ns",
		SyncPeriod: time.Minute,
		Node:       "test-node",
		AddResourceMetadata: &metadata.AddResourceMetadataConfig{
			CronJob:    false,
			Deployment: true,
		},
	}

	metricset := "replicaset"
	log := logptest.NewTestingLogger(t, selector)

	commonMetaConfig := metadata.Config{}
	commonConfig, _ := conf.NewConfigFrom(&commonMetaConfig)
	client := k8sfake.NewSimpleClientset()
	generalMetaGen := metadata.NewResourceMetadataGenerator(commonConfig, client)

	updateFunc := getEventMetadataFunc(log, generalMetaGen, nil)

	deleteFunc := func(r kubernetes.Resource) []string {
		accessor, _ := meta.Accessor(r)
		id := accessor.GetName()
		namespace := accessor.GetNamespace()
		if namespace != "" {
			id = join(namespace, id)
		}
		return []string{id}
	}

	indexFunc := func(e mapstr.M) string {
		name := getString(e, "name")
		namespace := getString(e, mb.ModuleDataKey+".namespace")
		var id string
		if name != "" && namespace != "" {
			id = join(namespace, name)
		} else if namespace != "" {
			id = namespace
		} else {
			id = name
		}
		return id
	}

	enricher := buildMetadataEnricher(metricset, ReplicaSetResource, resourceWatchers, config,
		updateFunc, deleteFunc, indexFunc, log)

	enricher.Start(resourceWatchers)
	resourceWatchers.lock.Lock()
	require.True(t, watcher.started)
	resourceWatchers.lock.Unlock()

	// manually run the transform function here, just like the actual informer
	transformed, err := transformReplicaSetMetadata(resource)
	require.NoError(t, err)
	watcher.watcher.GetEventHandler().OnAdd(transformed)
	err = watcher.watcher.Store().Add(transformed)
	require.NoError(t, err)

	// Test enricher
	events := []mapstr.M{
		// {"name": "unknown"},
		{"name": resource.Name, mb.ModuleDataKey + ".namespace": resource.Namespace},
	}
	enricher.Enrich(events)

	require.Equal(t, []mapstr.M{
		// {"name": "unknown"},
		{
			"name": "enrich",
			"_module": mapstr.M{
				"labels":     mapstr.M{"label": "value"},
				"replicaset": mapstr.M{"name": "enrich", "uid": "mockuid"},
				"namespace":  resource.Namespace,
				"deployment": mapstr.M{
					"name": "enrich_deployment",
				},
			},
			mb.ModuleDataKey + ".namespace": resource.Namespace,
			"meta":                          mapstr.M{},
		},
	}, events)

	watcher.watcher.GetEventHandler().OnDelete(resource)
	err = watcher.watcher.Store().Delete(resource)
	require.NoError(t, err)

	events = []mapstr.M{
		{"name": "enrich"},
	}
	enricher.Enrich(events)

	require.Equal(t, []mapstr.M{
		{"name": "enrich"},
	}, events)

	enricher.Stop(resourceWatchers)
	resourceWatchers.lock.Lock()
	require.False(t, watcher.started)
	resourceWatchers.lock.Unlock()
}

func TestGetWatcherStoreKeyFromMetadataKey(t *testing.T) {
	t.Run("global resource", func(t *testing.T) {
		assert.Equal(t, "name", getWatcherStoreKeyFromMetadataKey("name"))
	})
	t.Run("namespaced resource", func(t *testing.T) {
		assert.Equal(t, "namespace/name", getWatcherStoreKeyFromMetadataKey("namespace/name"))
	})
	t.Run("container", func(t *testing.T) {
		assert.Equal(t, "namespace/pod", getWatcherStoreKeyFromMetadataKey("namespace/pod/container"))
	})
}

type mockFuncs struct {
	updated kubernetes.Resource
	deleted kubernetes.Resource
	indexed mapstr.M
}

func (f *mockFuncs) update(obj kubernetes.Resource) map[string]mapstr.M {
	accessor, _ := meta.Accessor(obj)
	f.updated = obj
	meta := mapstr.M{
		"kubernetes": mapstr.M{
			"pod": mapstr.M{
				"name": accessor.GetName(),
				"uid":  string(accessor.GetUID()),
			},
		},
	}
	logger := logp.NewLogger("kubernetes")
	for k, v := range accessor.GetLabels() {
		kubernetes2.ShouldPut(meta, fmt.Sprintf("kubernetes.%v", k), v, logger)
	}
	kubernetes2.ShouldPut(meta, "orchestrator.cluster.name", "gke-4242", logger)
	id := accessor.GetName()
	return map[string]mapstr.M{id: meta}
}

func (f *mockFuncs) delete(obj kubernetes.Resource) []string {
	accessor, _ := meta.Accessor(obj)
	f.deleted = obj
	return []string{accessor.GetName()}
}

func (f *mockFuncs) index(m mapstr.M) string {
	f.indexed = m
	return m["name"].(string)
}

type mockWatcher struct {
	handler kubernetes.ResourceEventHandler
	store   cache.Store
}

func newMockWatcher() *mockWatcher {
	return &mockWatcher{
		store: cache.NewStore(func(obj interface{}) (string, error) {
			objName, err := cache.ObjectToName(obj)
			if err != nil {
				return "", err
			}
			return objName.Name, nil
		}),
	}
}

func (m *mockWatcher) GetEventHandler() kubernetes.ResourceEventHandler {
	return m.handler
}

func (m *mockWatcher) Start() error {
	return nil
}

func (m *mockWatcher) Stop() {

}

func (m *mockWatcher) AddEventHandler(r kubernetes.ResourceEventHandler) {
	m.handler = r
}

func (m *mockWatcher) Store() cache.Store {
	return m.store
}

func (m *mockWatcher) Client() k8s.Interface {
	return nil
}

func (m *mockWatcher) CachedObject() runtime.Object {
	return nil
}
