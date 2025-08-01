This metricset is available on Linux only and requires kernel 2.6.14 or newer.

The system `socket` metricset reports an event for each new TCP socket that it sees. It does this by polling the kernel periodically to get a dump of all sockets. You set the polling interval by configuring the `period` option. Specifying a short polling interval with this metricset is important to avoid missing short-lived connections. For example:

```yaml
metricbeat.modules:
- module: system
  metricsets: [cpu, memory]
- module: system
  metricsets: [socket] <1>
  period: 1s
```

1. You can configure the `socket` metricset separately to specify a different `period` value than the other metricsets.


The metricset reports the process that has the socket open. To provide this information on Linux for all processes, Metricbeat must be run with `sys_ptrace` and `dac_read_search` capabilities. These permissions are usually granted when running as root, but they can and may need to be explictly added when running Metricbeat inside a container.


## Configuration [_configuration_15]

```yaml
- module: system
  metricsets: [socket]
  socket.reverse_lookup.enabled: false
  socket.reverse_lookup.success_ttl: 60s
  socket.reverse_lookup.failure_ttl: 60s
```

**`socket.reverse_lookup.enabled`**
:   You can configure the metricset to perform a reverse lookup on the remote IP, and the returned hostname will be added to the event and cached. If a hostname is found, then the eTLD+1 (effective top-level domain plus one level) value will also be added to the event. Reverse lookups are disabled by default.

**`socket.reverse_lookup.success_ttl`**
:   The results of successful reverse lookups are cached for the period of time defined by this option. The default value is 60s.

**`socket.reverse_lookup.failure_ttl`**
:   The results of failed reverse lookups are cached for the period of time defined by this option. The default value is 60s.
