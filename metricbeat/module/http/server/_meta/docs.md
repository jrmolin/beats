This is the server metricset of the module http.

Events sent to the http endpoint will be put by default under the `http.server` prefix. To change this use the `server.paths` config options. In the example below every request to `/foo` will be put under `http.foo`. Also consider using secure settings for the server using TLS/SSL as shown

```yaml
- module: http
  metricsets: ["server"]
  host: "localhost"
  ssl.certificate: "/etc/pki/server/cert.pem"
  ssl.key: "/etc/pki/server/cert.key"
  port: "8080"
  server.paths:
    - path: "/foo"
      namespace: "foo"
```
