---
navigation_title: "add_nomad_metadata"
mapped_pages:
  - https://www.elastic.co/guide/en/beats/filebeat/current/add-nomad-metadata.html
applies_to:
  stack: preview
---

# Add Nomad metadata [add-nomad-metadata]


::::{warning}
This functionality is in technical preview and may be changed or removed in a future release. Elastic will work to fix any issues, but features in technical preview are not subject to the support SLA of official GA features.
::::


The `add_nomad_metadata` processor adds fields with relevant metadata for applications deployed in Nomad.

Each event is annotated with the following information:

* Allocation name, identifier and status.
* Job name and type.
* Namespace where the job is deployed.
* Datacenter and region where the agent running the allocation is located.

```yaml
processors:
  - add_nomad_metadata: ~
```

It has the following settings to configure the connection:

`address`
:   (Optional) The URL of the agent API used to request the metadata. It uses `http://127.0.0.1:4646` by default.

`namespace`
:   (Optional) Namespace to watch. If set, only events for allocations in this namespace will be annotated.

`region`
:   (Optional) Region to watch. If set, only events for allocations in this region will be annotated.

`secret_id`
:   (Optional) SecretID to use when connecting with the agent API. This is an example ACL policy to apply to the token.

```json
namespace "*" {
  policy = "read"
}
node {
  policy = "read"
}
agent {
  policy = "read"
}
```

`refresh_interval`
:   (Optional) Interval used to update the cached metadata. It defaults to 30 seconds.

`cleanup_timeout`
:   (Optional) After an allocation has been removed, time to wait before cleaning up their associated resources. This is useful if you expect to receive events after an allocation has been removed, which can happen when collecting logs. It defaults to 60 seconds.

You can decide if Filebeat should annotate events related to allocations in local node or on the whole cluster configuring the scope with the following settings:

`scope`
:   (Optional) Scope of the resources to watch. It can be `node` to get metadata only for the allocations in a single agent, or `global`, to get metadata for allocations running on any agent. It defaults to `node`.

`node`
:   (Optional) When using `scope: node`, use `node` to specify the name of the local node if it cannot be discovered automatically.

For example the following configuration could be used if Filebeat is collecting events from all the allocations in the cluster:

```yaml
processors:
  - add_nomad_metadata:
      scope: global
```

## Indexers and matchers [_indexers_and_matchers]

Indexers and matchers are used to correlate fields in events with actual metadata. Filebeat uses this information to know what metadata to include in each event.

### Indexers [_indexers_2]

Indexers use allocation metadata to create unique identifiers for each one of the pods.

Avaliable indexers are:

`allocation_name`
:   Identifies allocations by its name and namespace (as `<namespace>/<name>`)

`allocation_uuid`
:   Identifies allocations by its unique identifier.


### Matchers [_matchers_2]

Matchers are used to construct the lookup keys that match with the identifiers created by indexes.


### `field_format` [_field_format_2]

Looks up allocation metadata using a key created with a string format that can include event fields.

This matcher has an option `format` to define the string format. This string format can contain placeholders for any field in the event.

For example, the following configuration uses the `allocation_name` indexer to identify the allocation metadata by its name and namespace, and uses custom fields existing in the event as match keys:

```yaml
processors:
- add_nomad_metadata:
    ...
    default_indexers.enabled: false
    default_matchers.enabled: false
    indexers:
      - allocation_name:
    matchers:
      - field_format:
          format: '%{[labels.nomad_namespace]}/%{[fields.nomad_alloc_name]}'
```


### `fields` [_fields_2]

Looks up allocation metadata using as key the value of some specific fields. When multiple fields are defined, the first one included in the event is used.

This matcher has an option `lookup_fields` to define the fields whose value will be used for lookup.

For example, the following configuration uses the `allocation_uuid` indexer to identify allocations, and defines a matcher that uses some fields where the allocation UUID can be found for lookup, the first it finds in the event:

```yaml
processors:
- add_nomad_metadata:
    ...
    default_indexers.enabled: false
    default_matchers.enabled: false
    indexers:
      - allocation_uuid:
    matchers:
      - fields:
          lookup_fields: ['host.name', 'fields.nomad_alloc_uuid']
```


### `logs_path` [_logs_path_2]

Looks up allocation metadata using identifiers extracted from the log path stored in the `log.file.path` field.

This matcher has an optional `logs_path` option with the base path of the directory containing the logs for the local agent.

The default configuration is able to lookup the metadata using the allocation UUID when the logs are collected under `/var/lib/nomad`.

For example the following configuration would use the allocation UUID when the logs are collected from `/var/lib/NomadClient001/alloc/<alloc UUID>/alloc/logs/...`.

```yaml
processors:
- add_nomad_metadata:
    ...
    default_indexers.enabled: false
    default_matchers.enabled: false
    indexers:
      - allocation_uuid:
    matchers:
      - logs_path:
          logs_path: '/var/lib/NomadClient001'
```



