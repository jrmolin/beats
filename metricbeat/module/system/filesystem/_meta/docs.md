The System `filesystem` metricset provides file system statistics. For each file system, one document is provided.

This metricset is available on:

* FreeBSD
* Linux
* macOS
* OpenBSD
* Windows


## Configuration [_configuration_7]

**`filesystem.ignore_types`** - An array of filesystem types to ignore. Metrics will not be collected from filesystems matching these types. If this option is not set, {{metricbeat}} ignores all types for virtual devices in systems where this information is available (e.g. all types marked as `nodev` in `/proc/filesystems` in Linux systems). This setting affects the `fsstats` metricset.

To have {{metricbeat}} report on all filesystems, regardless of type, set `filesystem.ignore_types` to an empty array (`[]`).

To ignore unavailable volumes, such as CD-ROM drives, on Windows include `unavailable` as a value in the array. To ignore unknown filesystems on Windows, include `unknown` as a value in the array.


## Filtering [_filtering]

There may be mounted filesystems that you don’t want {{metricbeat}} to report metrics on. One option is to configure {{metricbeat}} to ignore specific filesystem types. This can be accomplished by configuring `filesystem.ignore_types` with an array of filesystem types to ignore. In this example we are ignoring three types of filesystems.

```yaml
metricbeat.modules:
  - module: system
    period: 30s
    metricsets: ["filesystem"]
    filesystem.ignore_types: [nfs, smbfs, autofs]
```

A common approach is to ignore any `unavailable` or `unknown` filesystems on Windows. For example:

```yaml
metricbeat.modules:
  - module: system
    period: 30s
    metricsets: ["filesystem"]
    filesystem.ignore_types: [unavailable, unknown]
```

Another strategy to deal with these filesystems is to configure a `drop_event` processor that matches the `mount_point` using a regular expression. This type of filtering occurs after the data has been collected so it can be less efficient than specifying `filesystem.ignore_types`.

```yaml
metricbeat.modules:
  - module: system
    period: 30s
    metricsets: ["filesystem"]
    processors:
      - drop_event.when.regexp:
          system.filesystem.mount_point: '^/(sys|cgroup|proc|dev|etc|host)($|/)'
```
