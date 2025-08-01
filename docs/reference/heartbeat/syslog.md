---
navigation_title: "syslog"
mapped_pages:
  - https://www.elastic.co/guide/en/beats/heartbeat/current/syslog.html
applies_to:
  stack: ga
---

# Syslog [syslog]


The syslog processor parses RFC 3146 and/or RFC 5424 formatted syslog messages that are stored in a field. The processor itself does not handle receiving syslog messages from external sources. This is done through an input, such as the TCP input. Certain integrations, when enabled through configuration, will embed the syslog processor to process syslog messages, such as Custom TCP Logs and Custom UDP Logs.


## Configuration [_configuration]

The `syslog` processor parses RFC 3146 and/or RFC 5424 formatted syslog messages that are stored under the `field` key.

The supported configuration options are:

`field`
:   (Required) Source field containing the syslog message. Defaults to `message`.

`format`
:   (Optional) The syslog format to use, `rfc3164`, or `rfc5424`. To automatically detect the format from the log entries, set this option to `auto`. The default is `auto`.

`timezone`
:   (Optional) IANA time zone name(e.g. `America/New York`) or a fixed time offset (e.g. +0200) to use when parsing syslog timestamps that do not contain a time zone. `Local` may be specified to use the machine’s local time zone. Defaults to `Local`.

`overwrite_keys`
:   (Optional) A boolean that specifies whether keys that already exist in the event are overwritten by keys from the syslog message. The default value is `true`.

`ignore_missing`
:   (Optional) If `true` the processor will not return an error when a specified field does not exist. Defaults to `false`.

`ignore_failure`
:   (Optional) Ignore all errors produced by the processor. Defaults to `false`.

`tag`
:   (Optional) An identifier for this processor. Useful for debugging.

Example:

```yaml
processors:
  - syslog:
      field: message
```

```json
{
  "message": "<165>1 2022-01-11T22:14:15.003Z mymachine.example.com eventslog 1024 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] this is the message"
}
```

Will produce the following output:

```json
{
  "@timestamp": "2022-01-11T22:14:15.003Z",
  "log": {
    "syslog": {
      "priority": 165,
      "facility": {
        "code": 20,
        "name": "local4"
      },
      "severity": {
        "code": 5,
        "name": "Notice"
      },
      "hostname": "mymachine.example.com",
      "appname": "eventslog",
      "procid": "1024",
      "msgid": "ID47",
      "version": 1,
      "structured_data": {
        "exampleSDID@32473": {
          "iut":         "3",
          "eventSource": "Application",
          "eventID":     "1011"
        },
        "examplePriority@32473": {
          "class": "high"
        }
      }
    }
  },
  "message": "this is the message"
}
```


## Timestamps [_timestamps]

The RFC 3164 format accepts the following forms of timestamps:

* Local timestamp (`Mmm dd hh:mm:ss`):

    * `Jan 23 14:09:01`

* RFC-3339*:

    * `2003-10-11T22:14:15Z`
    * `2003-10-11T22:14:15.123456Z`
    * `2003-10-11T22:14:15-06:00`
    * `2003-10-11T22:14:15.123456-06:00`


**Note**: The local timestamp (for example, `Jan 23 14:09:01`) that accompanies an RFC 3164 message lacks year and time zone information. The time zone will be enriched using the `timezone` configuration option, and the year will be enriched using the Heartbeat system’s local time (accounting for time zones). Because of this, it is possible for messages to appear in the future. An example of when this might happen is logs generated on December 31 2021 are ingested on January 1 2022. The logs would be enriched with the year 2022 instead of 2021.

The RFC 5424 format accepts the following forms of timestamps:

* RFC-3339:

    * `2003-10-11T22:14:15Z`
    * `2003-10-11T22:14:15.123456Z`
    * `2003-10-11T22:14:15-06:00`
    * `2003-10-11T22:14:15.123456-06:00`


Formats with an asterisk (*) are a non-standard allowance.


## Structured Data [_structured_data]

For RFC 5424-formatted logs, if the structured data cannot be parsed according to RFC standards, the original structured data text will be prepended to the message field, separated by a space.


## Metrics [_metrics]

Internal metrics are available to assist with debugging efforts. The metrics are served from the metrics HTTP endpoint (for example: `http://localhost:5066/stats`) and are found under `processor.syslog.[instance ID]` or `processor.syslog.[tag]-[instance ID]` if a **tag** is provided. See [HTTP endpoint](/reference/heartbeat/http-endpoint.md) for more information on configuration the metrics HTTP endpoint.

For example, here are metrics from a processor with a **tag** of `log-input` and an **instance ID** of `1`:

```json
{
  "processor": {
    "syslog": {
      "log-input-1": {
        "failure": 10,
        "missing": 0,
        "success": 3
      }
    }
  }
}
```

`failure`
:   Measures the number of occurrences where a message was unable to be parsed.

`missing`
:   Measures the number of occurrences where an event was missing the required input field.

`success`
:   Measures the number of successfully parsed syslog messages.

