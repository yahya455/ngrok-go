## 1.8.0
- Adds the `WithPolicy` and `WithPolicyConfig` options for applying a Traffic Policy to an endpoint.

## 1.7.0

- Adds the `WithAppProtocol` option for labeled listeners and HTTP endpoints.

  This provides a protocol hint that can be used to enable support for HTTP/2 to
  the backend service.

## 1.6.0

- Adds support for remote stop of listener.

## 1.5.1

- Adds TLS Renegotiation to the backend `tls.Config`.

## 1.5.0

- Added new forwarding API. See `[Session].ListenAndForward` and `[Session].ListenAndServeHTTP`.
- Deprecates `WithHTTPServer` and `WithHTTPHandler`. Use `[Session].ListenAndServeHTTP` instead.

## 1.4.0

- Switch to `connect.ngrok-agent.com:443` as the default server address
- Add nicer error types that expose the ngrok error code

## 1.0.0 (2023-01-10)

Enhancements:

- Initial release
