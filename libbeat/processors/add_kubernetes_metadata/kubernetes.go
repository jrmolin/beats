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

//go:build linux || darwin || windows

package add_kubernetes_metadata

import (
	"fmt"
	"os"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"

	k8sclient "k8s.io/client-go/kubernetes"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes/metadata"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/processors"
)

const (
	timeout                = time.Second * 5
	selector               = "kubernetes"
	checkNodeReadyAttempts = 10
)

type kubernetesAnnotator struct {
	log                 *logp.Logger
	watcher             kubernetes.Watcher
	nsWatcher           kubernetes.Watcher
	nodeWatcher         kubernetes.Watcher
	rsWatcher           kubernetes.Watcher
	jobWatcher          kubernetes.Watcher
	indexers            *Indexers
	matchers            *Matchers
	cache               *cache
	kubernetesAvailable bool
	initOnce            sync.Once
}

func init() {
	processors.RegisterPlugin("add_kubernetes_metadata", New)

	// Register default indexers
	Indexing.AddIndexer(PodNameIndexerName, NewPodNameIndexer)
	Indexing.AddIndexer(PodUIDIndexerName, NewPodUIDIndexer)
	Indexing.AddIndexer(ContainerIndexerName, NewContainerIndexer)
	Indexing.AddIndexer(IPPortIndexerName, NewIPPortIndexer)
	Indexing.AddMatcher(FieldMatcherName, NewFieldMatcher)
	Indexing.AddMatcher(FieldFormatMatcherName, NewFieldFormatMatcher)
}

func isKubernetesAvailable(client k8sclient.Interface) (bool, error) {
	server, err := client.Discovery().ServerVersion()
	if err != nil {
		return false, err
	}
	logp.Info("%v: kubernetes env detected, with version: %v", "add_kubernetes_metadata", server)
	return true, nil
}

func isKubernetesAvailableWithRetry(client k8sclient.Interface) bool {
	connectionAttempts := 1
	for {
		kubernetesAvailable, err := isKubernetesAvailable(client)
		if kubernetesAvailable {
			return true
		}
		if connectionAttempts > checkNodeReadyAttempts {
			logp.Info("%v: could not detect kubernetes env: %v", "add_kubernetes_metadata", err)
			return false
		}
		time.Sleep(3 * time.Second)
		connectionAttempts += 1
	}
}

// kubernetesMetadataExist checks whether an event is already enriched with kubernetes metadata
func kubernetesMetadataExist(event *beat.Event) bool {
	if _, err := event.GetValue("kubernetes"); err != nil {
		return false
	}
	return true
}

// New constructs a new add_kubernetes_metadata processor.
func New(cfg *config.C, log *logp.Logger) (beat.Processor, error) {
	config, err := newProcessorConfig(cfg, Indexing)
	if err != nil {
		return nil, err
	}

	log = log.Named(selector).With("libbeat.processor", "add_kubernetes_metadata")
	processor := &kubernetesAnnotator{
		log:                 log,
		cache:               newCache(config.CleanupTimeout),
		kubernetesAvailable: false,
	}

	// complete processor's initialisation asynchronously to re-try on failing k8s client initialisations in case
	// the k8s node is not yet ready.
	go processor.init(config, cfg)

	return processor, nil
}

func newProcessorConfig(cfg *config.C, register *Register) (kubeAnnotatorConfig, error) {
	var config kubeAnnotatorConfig
	err := cfg.Unpack(&config)
	if err != nil {
		return config, fmt.Errorf("fail to unpack the kubernetes configuration: %w", err)
	}

	// Load and append default indexer configs
	if config.DefaultIndexers.Enabled {
		config.Indexers = append(config.Indexers, register.GetDefaultIndexerConfigs()...)
	}

	// Load and append default matcher configs
	if config.DefaultMatchers.Enabled {
		config.Matchers = append(config.Matchers, register.GetDefaultMatcherConfigs()...)
	}

	return config, nil
}

func (k *kubernetesAnnotator) init(config kubeAnnotatorConfig, cfg *config.C) {
	k.initOnce.Do(func() {
		var replicaSetWatcher, jobWatcher, namespaceWatcher, nodeWatcher kubernetes.Watcher

		// We initialise the use_kubeadm variable based on modules KubeAdm base configuration
		err := config.AddResourceMetadata.Namespace.SetBool("use_kubeadm", -1, config.KubeAdm)
		if err != nil {
			k.log.Errorf("couldn't set kubeadm variable for namespace due to error %+v", err)
		}
		err = config.AddResourceMetadata.Node.SetBool("use_kubeadm", -1, config.KubeAdm)
		if err != nil {
			k.log.Errorf("couldn't set kubeadm variable for node due to error %+v", err)
		}
		client, err := kubernetes.GetKubernetesClient(config.KubeConfig, config.KubeClientOptions)
		if err != nil {
			if kubernetes.IsInCluster(config.KubeConfig) {
				k.log.Debugf("Could not create kubernetes client using in_cluster config: %+v", err)
			} else if config.KubeConfig == "" {
				k.log.Debugf("Could not create kubernetes client using config: %v: %+v", os.Getenv("KUBECONFIG"), err)
			} else {
				k.log.Debugf("Could not create kubernetes client using config: %v: %+v", config.KubeConfig, err)
			}
			return
		}

		if !isKubernetesAvailableWithRetry(client) {
			return
		}

		matchers := NewMatchers(config.Matchers, k.log)

		if matchers.Empty() {
			k.log.Debugf("Could not initialize kubernetes plugin with zero matcher plugins")
			return
		}

		k.matchers = matchers
		nd := &kubernetes.DiscoverKubernetesNodeParams{
			ConfigHost:  config.Node,
			Client:      client,
			IsInCluster: kubernetes.IsInCluster(config.KubeConfig),
			HostUtils:   &kubernetes.DefaultDiscoveryUtils{},
		}
		if config.Scope == "node" {
			config.Node, err = kubernetes.DiscoverKubernetesNode(k.log, nd)
			if err != nil {
				k.log.Errorf("Couldn't discover Kubernetes node: %w", err)
				return
			}
			k.log.Debugf("Initializing a new Kubernetes watcher using host: %s", config.Node)
		}

		watcher, err := kubernetes.NewNamedWatcher("add_kubernetes_metadata_pod", client, &kubernetes.Pod{}, kubernetes.WatchOptions{
			SyncTimeout:  config.SyncPeriod,
			Node:         config.Node,
			Namespace:    config.Namespace,
			HonorReSyncs: true,
		}, nil, k.log)
		if err != nil {
			k.log.Errorf("Couldn't create kubernetes watcher for %T", &kubernetes.Pod{})
			return
		}

		metaConf := config.AddResourceMetadata

		if metaConf.Node.Enabled() {
			nodeWatcher, err = kubernetes.NewNamedWatcher("add_kubernetes_metadata_node", client, &kubernetes.Node{}, kubernetes.WatchOptions{
				SyncTimeout:  config.SyncPeriod,
				Node:         config.Node,
				HonorReSyncs: true,
			}, nil, k.log)
			if err != nil {
				k.log.Errorf("couldn't create watcher for %T due to error %+v", &kubernetes.Node{}, err)
			}
		}

		if metaConf.Namespace.Enabled() {
			namespaceWatcher, err = kubernetes.NewNamedWatcher("add_kubernetes_metadata_namespace", client, &kubernetes.Namespace{}, kubernetes.WatchOptions{
				SyncTimeout:  config.SyncPeriod,
				Namespace:    config.Namespace,
				HonorReSyncs: true,
			}, nil, k.log)
			if err != nil {
				k.log.Errorf("couldn't create watcher for %T due to error %+v", &kubernetes.Namespace{}, err)
			}
		}

		// Resource is Pod, so we need to create watchers for Replicasets and Jobs that it might belong to
		// in order to be able to retrieve 2nd layer Owner metadata like in case of:
		// Deployment -> Replicaset -> Pod
		// CronJob -> job -> Pod
		if metaConf.Deployment {
			metadataClient, err := kubernetes.GetKubernetesMetadataClient(config.KubeConfig, config.KubeClientOptions)
			if err != nil {
				k.log.Errorf("Error creating metadata client due to error %+v", err)
			}
			replicaSetWatcher, err = kubernetes.NewNamedMetadataWatcher(
				"resource_metadata_enricher_rs",
				client,
				metadataClient,
				schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"},
				kubernetes.WatchOptions{
					SyncTimeout:  config.SyncPeriod,
					Namespace:    config.Namespace,
					HonorReSyncs: true,
				},
				nil,
				metadata.RemoveUnnecessaryReplicaSetData,
				k.log,
			)
			if err != nil {
				k.log.Errorf("Error creating watcher for %T due to error %+v", &kubernetes.ReplicaSet{}, err)
			}
			k.rsWatcher = replicaSetWatcher
		}
		if metaConf.CronJob {
			jobWatcher, err = kubernetes.NewNamedWatcher("resource_metadata_enricher_job", client, &kubernetes.Job{}, kubernetes.WatchOptions{
				SyncTimeout:  config.SyncPeriod,
				Namespace:    config.Namespace,
				HonorReSyncs: true,
			}, nil, k.log)
			if err != nil {
				k.log.Errorf("Error creating watcher for %T due to error %+v", &kubernetes.Job{}, err)
			}
			k.jobWatcher = jobWatcher
		}

		// TODO: refactor the above section to a common function to be used by NeWPodEventer too
		metaGen := metadata.GetPodMetaGen(cfg, watcher, nodeWatcher, namespaceWatcher, replicaSetWatcher, jobWatcher, metaConf)

		k.indexers = NewIndexers(config.Indexers, metaGen)
		k.watcher = watcher
		k.kubernetesAvailable = true
		k.nodeWatcher = nodeWatcher
		k.nsWatcher = namespaceWatcher

		watcher.AddEventHandler(kubernetes.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod, _ := obj.(*kubernetes.Pod)
				k.addPod(pod)
			},
			UpdateFunc: func(obj interface{}) {
				pod, _ := obj.(*kubernetes.Pod)
				k.updatePod(pod)
			},
			DeleteFunc: func(obj interface{}) {
				pod, _ := obj.(*kubernetes.Pod)
				k.removePod(pod)
			},
		})

		// NOTE: order is important here since pod meta will include node meta and hence node.Store() should
		// be populated before trying to generate metadata for Pods.
		if k.nodeWatcher != nil {
			if err := k.nodeWatcher.Start(); err != nil {
				k.log.Debugf("add_kubernetes_metadata", "Couldn't start node watcher: %v", err)
				return
			}
		}
		if k.nsWatcher != nil {
			if err := k.nsWatcher.Start(); err != nil {
				k.log.Debugf("add_kubernetes_metadata", "Couldn't start namespace watcher: %v", err)
				return
			}
		}
		if k.rsWatcher != nil {
			if err := k.rsWatcher.Start(); err != nil {
				k.log.Debugf("add_kubernetes_metadata", "Couldn't start replicaSet watcher: %v", err)
				return
			}
		}
		if k.jobWatcher != nil {
			if err := k.jobWatcher.Start(); err != nil {
				k.log.Debugf("add_kubernetes_metadata", "Couldn't start job watcher: %v", err)
				return
			}
		}
		if err := watcher.Start(); err != nil {
			k.log.Debugf("add_kubernetes_metadata", "Couldn't start pod watcher: %v", err)
			return
		}
	})
}

// Run runs the processor that adds a field `kubernetes` to the event fields that
// contains a map with various Kubernetes metadata.
// This processor does not access or modify the `Meta` of the event.
func (k *kubernetesAnnotator) Run(event *beat.Event) (*beat.Event, error) {
	if !k.kubernetesAvailable {
		return event, nil
	}
	if kubernetesMetadataExist(event) {
		return event, nil
	}

	index := k.matchers.MetadataIndex(event.Fields)
	if index == "" {
		k.log.Debug("No container match string, not adding kubernetes data")
		return event, nil
	}

	metadata := k.cache.get(index)
	if metadata == nil {
		return event, nil
	}

	metaClone := metadata.Clone()
	_ = metaClone.Delete("kubernetes.container.name")
	containerImage, err := metadata.GetValue("kubernetes.container.image")
	if err == nil {
		_ = metaClone.Delete("kubernetes.container.image")
		_, _ = metaClone.Put("kubernetes.container.image.name", containerImage)
	}
	cmeta, err := metaClone.Clone().GetValue("kubernetes.container")
	if err == nil {
		event.Fields.DeepUpdate(mapstr.M{
			"container": cmeta,
		})
	}

	kubeMeta := metadata.Clone()
	// remove container meta from kubernetes.container.*
	_ = kubeMeta.Delete("kubernetes.container.id")
	_ = kubeMeta.Delete("kubernetes.container.runtime")
	_ = kubeMeta.Delete("kubernetes.container.image")
	event.Fields.DeepUpdate(kubeMeta)

	return event, nil
}

func (k *kubernetesAnnotator) Close() error {
	if k.watcher != nil {
		k.watcher.Stop()
	}
	if k.nodeWatcher != nil {
		k.nodeWatcher.Stop()
	}
	if k.nsWatcher != nil {
		k.nsWatcher.Stop()
	}
	if k.rsWatcher != nil {
		k.rsWatcher.Stop()
	}
	if k.jobWatcher != nil {
		k.jobWatcher.Stop()
	}
	if k.cache != nil {
		k.cache.stop()
	}
	return nil
}

func (k *kubernetesAnnotator) addPod(pod *kubernetes.Pod) {
	metadata := k.indexers.GetMetadata(pod)
	for _, m := range metadata {
		k.cache.set(m.Index, m.Data)
	}
}

func (k *kubernetesAnnotator) updatePod(pod *kubernetes.Pod) {
	k.removePod(pod)

	// Add it again only if it is not being deleted
	if pod.GetObjectMeta().GetDeletionTimestamp() != nil {
		return
	}

	k.addPod(pod)
}

func (k *kubernetesAnnotator) removePod(pod *kubernetes.Pod) {
	indexes := k.indexers.GetIndexes(pod)
	for _, idx := range indexes {
		k.cache.delete(idx)
	}
}

func (*kubernetesAnnotator) String() string {
	return "add_kubernetes_metadata"
}
