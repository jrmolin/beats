---
mapped_pages:
  - https://www.elastic.co/guide/en/beats/filebeat/current/configuration-output-codec.html
applies_to:
  stack: ga
---

# Change the output codec [configuration-output-codec]

For outputs that do not require a specific encoding, you can change the encoding by using the codec configuration. You can specify either the `json` or `format` codec. By default the `json` codec is used.

**`json.pretty`**: If `pretty` is set to true, events will be nicely formatted. The default is false.

**`json.escape_html`**: If `escape_html` is set to true, html symbols will be escaped in strings. The default is false.

Example configuration that uses the `json` codec with pretty printing enabled to write events to the console:

```yaml
output.console:
  codec.json:
    pretty: true
    escape_html: false
```

**`format.string`**: Configurable format string used to create a custom formatted message.

Example configurable that uses the `format` codec to print the events timestamp and message field to console:

```yaml
output.console:
  codec.format:
    string: '%{[@timestamp]} %{[message]}'
```

