---
mapped_pages:
  - https://www.elastic.co/guide/en/beats/packetbeat/current/error-loading-config.html
applies_to:
  stack: ga
---

# Error loading config file [error-loading-config]

You may encounter errors loading the config file on POSIX operating systems if:

* an unauthorized user tries to load the config file, or
* the config file has the wrong permissions.

See [Config File Ownership and Permissions](/reference/libbeat/config-file-permissions.md) for more about resolving these errors.

