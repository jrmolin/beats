---
navigation_title: "append"
mapped_pages:
  - https://www.elastic.co/guide/en/beats/winlogbeat/current/append.html
applies_to:
  stack: ga
---

# Append Processor [append]


The `append` processor appends one or more values to an existing array if the target field already exists and it is an array. Converts a scaler to an array and appends one or more values to it if the field exists and it is a scaler. Here the values can either be one or more static values or one or more values from the fields listed under *fields* key.

`target_field`
:   The field in which you want to append the data.

`fields`
:   (Optional) List of fields from which you want to copy data from. If the value is of a concrete type it will be appended directly to the target. However, if the value is an array, all the elements of the array are pushed individually to the target field.

`values`
:   (Optional) List of static values you want to append to target field.

`ignore_empty_values`
:   (Optional) If set to `true`, all the `""` and `nil` are omitted from being appended to the target field.

`fail_on_error`
:   (Optional) If set to `true` and an error occurs, the changes are reverted and the original is returned. If set to `false`, processing continues if an error occurs. Default is `true`.

`allow_duplicate`
:   (Optional) If set to `false`, the processor does not append values already present in the field. The default is `true`, which will append duplicate values in the array.

`ignore_missing`
:   (Optional) Indicates whether to ignore events that lack the source field. The default is `false`, which will fail processing of an event if a field is missing.

note: If you want to use `fields` parameter with fields under `message`, make sure you use `decode_json_fields` first with `target: ""`.

For example, this configuration:

```yaml
processors:
  - decode_json_fields:
      fields: message
      target: ""
  - append:
      target_field: target-field
      fields:
        - concrete.field
        - array.one
      values:
        - static-value
        - ""
      ignore_missing: true
      fail_on_error: true
      ignore_empty_values: true
```

Copies the values of `concrete.field`, `array.one` response fields and the static values to `target-field`:

```json
{
  "concrete": {
    "field": "val0"
  },
  "array": {
      "one": [ "val1", "val2" ]
  },
  "target-field": [
    "val0",
    "val1",
    "val2",
    "static-value"
  ]
}
```

