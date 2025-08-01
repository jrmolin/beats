---
mapped_pages:
  - https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-deduplication.html
applies_to:
  stack: ga
---

# Deduplicate data [filebeat-deduplication]

The {{beats}} framework guarantees at-least-once delivery to ensure that no data is lost when events are sent to outputs that support acknowledgement, such as {{es}}, {{ls}}, Kafka, and Redis. This is great if everything goes as planned. But if Filebeat shuts down during processing, or the connection is lost before events are acknowledged, you can end up with duplicate data.


## What causes duplicates in {{es}}? [_what_causes_duplicates_in_es]

When an output is blocked, the retry mechanism in Filebeat attempts to resend events until they are acknowledged by the output. If the output receives the events, but is unable to acknowledge them, the data might be sent to the output multiple times. Because document IDs are typically set by {{es}} *after* it receives the data from {{beats}}, the duplicate events are indexed as new documents.


## How can I avoid duplicates? [_how_can_i_avoid_duplicates]

Rather than allowing {{es}} to set the document ID, set the ID in {{beats}}. The ID is stored in the {{beats}} `@metadata._id` field and used to set the document ID during indexing. That way, if {{beats}} sends the same event to {{es}} more than once, {{es}} overwrites the existing document rather than creating a new one.

The `@metadata._id` field is passed along with the event so that you can use it to set the document ID after the event has been published by Filebeat but before it’s received by {{es}}. For example, see [{{ls}} pipeline example](#ls-doc-id).

There are several ways to set the document ID in {{beats}}:

* **`add_id` processor**

    Use the [`add_id`](/reference/filebeat/add-id.md) processor when your data has no natural key field, and you can’t derive a unique key from existing fields.

    This example generates a unique ID for each event and adds it to the `@metadata._id` field:

    ```yaml
    processors:
      - add_id: ~
    ```

* **`fingerprint` processor**

    Use the [`fingerprint`](/reference/filebeat/fingerprint.md) processor to derive a unique key from one or more existing fields.

    This example uses the values of `field1` and `field2` to derive a unique key that it adds to the `@metadata._id` field:

    ```yaml
    processors:
      - fingerprint:
          fields: ["field1", "field2"]
          target_field: "@metadata._id"
    ```

* **`decode_json_fields` processor**

    Use the `document_id` setting in the [`decode_json_fields`](/reference/filebeat/decode-json-fields.md) processor when you’re decoding a JSON string that contains a natural key field.

    For this example, assume that the `message` field contains the JSON string `{"myid": "100", "text": "Some text"}`. This example takes the value of `myid` from the JSON string and stores it in the `@metadata._id` field:

    ```yaml
    processors:
      - decode_json_fields:
          document_id: "myid"
          fields: ["message"]
          max_depth: 1
          target: ""
    ```

    The resulting document ID is `100`.

* **JSON input settings**

    Use the `json.document_id` input setting if you’re ingesting JSON-formatted data, and the data has a natural key field.

    This example takes the value of `key1` from the JSON document and stores it in the `@metadata._id` field:

    ```yaml
    filebeat.inputs:
    - type: log
      paths:
        - /path/to/json.log
      json.document_id: "key1"
    ```



## {{ls}} pipeline example [ls-doc-id]

For this example, assume that you’ve used one of the approaches described earlier to store the document ID in the {{beats}} `@metadata._id` field. To preserve the ID when you send {{beats}} data through {{ls}} en route to {{es}}, set the `document_id` field in the {{ls}} pipeline:

```json
input {
  beats {
    port => 5044
  }
}

output {
  if [@metadata][_id] {
    elasticsearch {
      hosts => ["http://localhost:9200"]
      document_id => "%{[@metadata][_id]}" <1>
      index => "%{[@metadata][beat]}-%{[@metadata][version]}"
    }
  } else {
    elasticsearch {
      hosts => ["http://localhost:9200"]
      index => "%{[@metadata][beat]}-%{[@metadata][version]}"
    }
  }
}
```

1. Sets the `document_id` field in the [{{es}} output](logstash-docs-md://lsr/plugins-outputs-elasticsearch.md) to the value stored in `@metadata._id`.


When {{es}} indexes the document, it sets the document ID to the specified value, preserving the ID passed from {{beats}}.

