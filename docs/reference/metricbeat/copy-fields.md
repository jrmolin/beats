---
navigation_title: "copy_fields"
mapped_pages:
  - https://www.elastic.co/guide/en/beats/metricbeat/current/copy-fields.html
applies_to:
  stack: ga
---

# Copy fields [copy-fields]


The `copy_fields` processor takes the value of a field and copies it to a new field.

You cannot use this processor to replace an existing field. If the target field already exists, you must [drop](/reference/metricbeat/drop-fields.md) or [rename](/reference/metricbeat/rename-fields.md) the field before using `copy_fields`.

`fields`
:   List of `from` and `to` pairs to copy from and to. It’s supported to use `@metadata.` prefix for `from` and `to` and copy values not just in/from/to the event fields but also in/from/to the event metadata.

`fail_on_error`
:   (Optional) If set to `true` and an error occurs, the changes are reverted and the original is returned. If set to `false`, processing continues if an error occurs. Default is `true`.

`ignore_missing`
:   (Optional) Indicates whether to ignore events that lack the source field. The default is `false`, which will fail processing of an event if a field is missing.

For example, this configuration:

```yaml
processors:
  - copy_fields:
      fields:
        - from: message
          to: event.original
      fail_on_error: false
      ignore_missing: true
```

Copies the original `message` field to `event.original`:

```json
{
  "message": "my-interesting-message",
  "event": {
      "original": "my-interesting-message"
  }
}
```

