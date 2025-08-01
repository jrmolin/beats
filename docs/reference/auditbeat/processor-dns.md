---
navigation_title: "dns"
mapped_pages:
  - https://www.elastic.co/guide/en/beats/auditbeat/current/processor-dns.html
applies_to:
  stack: ga
---

# DNS Reverse Lookup [processor-dns]


The `dns` processor performs DNS queries. It caches the responses that it receives in accordance to the time-to-live (TTL) value contained in the response. It also caches failures that occur during lookups. Each instance of this processor maintains its own independent cache.

The processor uses its own DNS resolver to send requests to nameservers and does not use the operating system’s resolver. It does not read any values contained in `/etc/hosts`.

This processor can significantly slow down your pipeline’s throughput if you have a high latency network or slow upstream nameserver. The cache will help with performance, but if the addresses being resolved have a high cardinality then the cache benefits will be diminished due to the high miss ratio.

By way of example, if each DNS lookup takes 2 milliseconds, the maximum throughput you can achieve is 500 events per second (1000 milliseconds / 2 milliseconds). If you have a high cache hit ratio then your throughput can be higher.

The processor can send the following query types:

* `A` - IPv4 addresses
* `AAAA` - IPv6 addresses
* `TXT` - arbitrary human-readable text data
* `PTR` - reverse IP address lookups

The output value is a list of strings for all query types except `PTR`. For `PTR` queries the output value is a string.

This is a minimal configuration example that resolves the IP addresses contained in two fields.

```yaml
processors:
  - dns:
      type: reverse
      fields:
        source.ip: source.domain
        destination.ip: destination.domain
```

Next is a configuration example showing all options.

```yaml
processors:
- dns:
    type: reverse
    action: append
    transport: tls
    fields:
      server.ip: server.domain
      client.ip: client.domain
    success_cache:
      capacity.initial: 1000
      capacity.max: 10000
      min_ttl: 1m
    failure_cache:
      capacity.initial: 1000
      capacity.max: 10000
      ttl: 1m
    nameservers: ['192.0.2.1', '203.0.113.1']
    timeout: 500ms
    tag_on_failure: [_dns_reverse_lookup_failed]
```

The `dns` processor has the following configuration settings:

`type`
:   The type of DNS query to perform. The supported types are `A`, `AAAA`, `PTR` (or `reverse`), and `TXT`.

`action`
:   This defines the behavior of the processor when the target field already exists in the event. The options are `append` (default) and `replace`.

`fields`
:   This is a mapping of source field names to target field names. The value of the source field will be used in the DNS query and result will be written to the target field.

`success_cache.capacity.initial`
:   The initial number of items that the success cache will be allocated to hold. When initialized the processor will allocate the memory for this number of items. Default value is `1000`.

`success_cache.capacity.max`
:   The maximum number of items that the success cache can hold. When the maximum capacity is reached a random item is evicted. Default value is `10000`.

`success_cache.min_ttl`
:   The duration of the minimum alternative cache TTL for successful DNS responses. Ensures that `TTL=0` successful reverse DNS responses can be cached. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h". Default value is `1m`.

`success_cache.enabled` {applies_to}`stack: ga 9.1.0`
:   Whether the success cache should be enabled. The default value is `true`, meaning the cache is used by default.

::::{note}
Disabling the cache has throughput implications, requiring each event to perform a round trip to the DNS server. For example, if a DNS lookup takes 1 ms, serial throughput is limited to a maximum of 1,000 events per second.
::::

`failure_cache.capacity.initial`
:   The initial number of items that the failure cache will be allocated to hold. When initialized the processor will allocate the memory for this number of items. Default value is `1000`.

`failure_cache.capacity.max`
:   The maximum number of items that the failure cache can hold. When the maximum capacity is reached a random item is evicted. Default value is `10000`.

`failure_cache.ttl`
:   The duration for which failures are cached. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h". Default value is `1m`.

`failure_cache.enabled` {applies_to}`stack: ga 9.1.0`
:   Whether the failure cache should be enabled. The default value is `true`, meaning the cache is used by default.

::::{note}
Disabling the cache has throughput implications, requiring each event to perform a round trip to the DNS server. For example, if a DNS lookup takes 1 ms, serial throughput is limited to a maximum of 1,000 events per second. Additionally, if the failure occurs because the server is overloaded, retrying immediately might have compounding effects.
::::

`nameservers`
:   A list of nameservers to query. If there are multiple servers, the resolver queries them in the order listed. If none are specified then it will read the nameservers listed in `/etc/resolv.conf` once at initialization. On Windows you must always supply at least one nameserver.

`timeout`
:   The duration after which a DNS query will timeout. This is timeout for each DNS request so if you have 2 nameservers then the total timeout will be 2 times this value. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h". Default value is `500ms`.

`tag_on_failure`
:   A list of tags to add to the event when any lookup fails. The tags are only added once even if multiple lookups fail. By default, no tags are added upon failure.

`transport`
:   The type of transport connection that should be used can either be `tls` (DNS over TLS) or `udp`. Defaults to `udp`.

