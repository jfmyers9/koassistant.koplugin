# HTTPS verification

The local patch on top of v0.23.0 routes provider requests, OpenAI device-login
and refresh requests, and updater requests through verified TLS. LuaSec 1.3.2
does not verify peer certificates by default and does not check their hostnames
when `verify = "peer"` is set, so both checks are required.

`koassistant_https.lua` provides the shared connection and request helpers:

- Require a trusted, currently valid certificate chain (`verify = "peer"`).
- Match DNS or IP subjectAltNames before sending HTTP headers or bodies. DNS
  wildcards must occupy exactly one complete leftmost label; IP literals match
  only IP SANs. Legacy CN-only certificates are deliberately rejected.
- Use `SSL_CERT_FILE` when explicitly set, otherwise KOReader's bundled
  `data/ca-bundle.crt`, then common system CA locations. A missing or invalid
  trust store fails closed. For a private CA, supply a bundle containing its root
  alongside the public roots; do not disable verification.
- Support KOReader's configured plain HTTP proxy through CONNECT, with TLS and
  hostname verification inside the tunnel. HTTPS proxies and proxy URL
  credentials are currently rejected, not silently bypassed. This supports the
  shape of the Tailscale loopback proxy, but is not an on-device Tailscale test.
- Reject automatic redirects for requests carrying provider/OAuth credentials.
  A moved API endpoint must be explicitly updated. Public updater GETs on the
  LuaSocket path may follow up to five HTTPS redirects, checking every peer and
  accepting only non-credential headers. Intermediate bodies are discarded;
  public downloads are bounded to 64 MiB. The pre-existing raw macOS updater
  path still returns redirects instead of following them.
- Keep the existing macOS pre-resolved FFI connection path, including resolution
  of the proxy instead of the origin when tunneling. Both the native and
  LuaSocket connection paths share the same verification helper.

Plain HTTP custom endpoints (e.g. a deliberately configured local Ollama server)
are unchanged: they are **not encrypted or authenticated by TLS**. Use HTTPS or a
separately secured network for those. A pinned plugin with these transport fixes
is not a security audit of every plugin feature. OAuth account compatibility,
provider service terms and on-device operation remain separate concerns.

## Tests

Fast unit tests (part of `tests/run_tests.lua --unit`):

```sh
luajit -e 'assert(dofile("tests/unit/test_https.lua"))'
```

Loopback integration tests use real LuaSocket/LuaSec/OpenSSL, disposable root
certificates, HTTPS servers and a CONNECT proxy. No account, API key, real book,
or outside network request is involved:

```sh
# LuaSocket, LuaSec 1.3.2+, and dkjson must be on LUA_PATH/LUA_CPATH.
# Python 3 and an openssl executable are also required.
python3 tests/tools/test_https_transport.py
```

The test exercises requests, the one-shot/OAuth transport, the streaming provider
worker, and the raw connection helper (including the pre-resolved native socket)
directly and through a proxy. Trusted certificates succeed; self-signed, expired
and wrong-host certificates fail without the server receiving any HTTP
credentials. It also tests IP SANs, missing CA bundles, proxy refusal, and
redirect policy. KOReader's GUI and actual fork lifecycle are not exercised.

Use `LUA` and `OPENSSL` to select test executables if necessary. The script creates
and removes its private test keys automatically. Do not run the provider suite
without `--unit` unless real API calls and their costs are intended.
