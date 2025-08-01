---
navigation_title: "convert"
mapped_pages:
  - https://www.elastic.co/guide/en/beats/heartbeat/current/convert.html
applies_to:
  stack: ga
---

# Convert [convert]


The `convert` processor converts a field in the event to a different type, such as converting a string to an integer.

The supported types include: `integer`, `long`, `float`, `double`, `string`, `boolean`, and `ip`.

The `ip` type is effectively an alias for `string`, but with an added validation that the value is an IPv4 or IPv6 address.

```yaml
processors:
  - convert:
      fields:
        - {from: "src_ip", to: "source.ip", type: "ip"}
        - {from: "src_port", to: "source.port", type: "integer"}
      ignore_missing: true
      fail_on_error: false
```

The `convert` processor has the following configuration settings:

`fields`
:   (Required) This is the list of fields to convert. At least one item must be contained in the list. Each item in the list must have a `from` key that specifies the source field. The `to` key is optional and specifies where to assign the converted value. If `to` is omitted then the `from` field is updated in-place. The `type` key specifies the data type to convert the value to. If `type` is omitted then the processor copies or renames the field without any type conversion.

`ignore_missing`
:   (Optional) If `true` the processor continues to the next field when the `from` key is not found in the event. If false then the processor returns an error and does not process the remaining fields. Default is `false`.

`fail_on_error`
:   (Optional) If false type conversion failures are ignored and the processor continues to the next field. Default is `true`.

`tag`
:   (Optional) An identifier for this processor. Useful for debugging.

`mode`
:   (Optional) When both `from` and `to` are defined for a field then `mode` controls whether to `copy` or `rename` the field when the type conversion is successful. Default is `copy`.

