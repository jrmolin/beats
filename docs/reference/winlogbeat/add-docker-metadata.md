---
navigation_title: "add_docker_metadata"
mapped_pages:
  - https://www.elastic.co/guide/en/beats/winlogbeat/current/add-docker-metadata.html
applies_to:
  stack: ga
---

# Add Docker metadata [add-docker-metadata]


The `add_docker_metadata` processor annotates each event with relevant metadata from Docker containers. At startup it detects a docker environment and caches the metadata. The events are annotated with Docker metadata, only if a valid configuration is detected and the processor is able to reach Docker API.

Each event is annotated with:

* Container ID
* Name
* Image
* Labels

::::{note}
When running Winlogbeat in a container, you need to provide access to Docker’s unix socket in order for the `add_docker_metadata` processor to work. You can do this by mounting the socket inside the container. For example:

`docker run -v /var/run/docker.sock:/var/run/docker.sock ...`

To avoid privilege issues, you may also need to add `--user=root` to the `docker run` flags. Because the user must be part of the docker group in order to access `/var/run/docker.sock`, root access is required if Winlogbeat is running as non-root inside the container.

If Docker daemon is restarted the mounted socket will become invalid and metadata will stop working, in these situations there are two options:

* Restart Winlogbeat every time Docker is restarted
* Mount the entire `/var/run` directory (instead of just the socket)

::::


```yaml
processors:
  - add_docker_metadata:
      host: "unix:///var/run/docker.sock"
      #match_fields: ["system.process.cgroup.id"]
      #match_pids: ["process.pid", "process.parent.pid"]
      #match_source: true
      #match_source_index: 4
      #match_short_id: true
      #cleanup_timeout: 60
      #labels.dedot: false
      # To connect to Docker over TLS you must specify a client and CA certificate.
      #ssl:
      #  certificate_authority: "/etc/pki/root/ca.pem"
      #  certificate:           "/etc/pki/client/cert.pem"
      #  key:                   "/etc/pki/client/cert.key"
```

It has the following settings:

`host`
:   (Optional) Docker socket (UNIX or TCP socket). It uses `unix:///var/run/docker.sock` by default.

`ssl`
:   (Optional) SSL configuration to use when connecting to the Docker socket.

`match_fields`
:   (Optional) A list of fields to match a container ID, at least one of them should hold a container ID to get the event enriched.

`match_pids`
:   (Optional) A list of fields that contain process IDs. If the process is running in Docker then the event will be enriched. The default value is `["process.pid", "process.parent.pid"]`.

`match_source`
:   (Optional) Match container ID from a log path present in the `log.file.path` field. Enabled by default.

`match_short_id`
:   (Optional) Match container short ID from a log path present in the `log.file.path` field. Disabled by default. This allows to match directories names that have the first 12 characters of the container ID. For example, `/var/log/containers/b7e3460e2b21/*.log`.

`match_source_index`
:   (Optional) Index in the source path split by `/` to look for container ID. It defaults to 4 to match `/var/lib/docker/containers/<container_id>/*.log`

`cleanup_timeout`
:   (Optional) Time of inactivity to consider we can clean and forget metadata for a container, 60s by default.

`labels.dedot`
:   (Optional) Default to be false. If set to true, replace dots in labels with `_`.

