# Reference peers

Real implementations of the protocols these packages speak, used so the PHP side is tested
against something other than itself. A protect/unprotect or encode/decode round trip inside
one codebase passes just as happily when both halves share a misreading of the spec.

Each peer reads one JSON request per line on stdin and writes one JSON response per line on
stdout, so a PHP test can drive many vectors through a single process with `proc_open`.

## Building

```sh
go build -o bin/refpeer-srtp ./cmd/refpeer-srtp
```

Tests skip themselves when the binary is absent, so a checkout without a Go toolchain still
runs everything that does not need a peer. Set `PHP_RTC_REFERENCE_BIN` to override the path.

## Peers

| Binary | Backed by | Used by |
| --- | --- | --- |
| `refpeer-srtp` | `pion/srtp` | `srtp` |

STUN and TURN are covered by coturn rather than a peer here, using the configuration in
`ice/tests/turnconfig/`:

```sh
podman run -d --name phprtc-coturn --network host \
  -v "$PWD/../ice/tests/turnconfig/turnserver.conf:/etc/turnserver/turnserver.conf:ro" \
  -v "$PWD/../ice/tests/turnconfig/turnserver.crt:/etc/turnserver/turnserver.crt:ro" \
  -v "$PWD/../ice/tests/turnconfig/turnserver.key:/etc/turnserver/turnserver.key:ro" \
  docker.io/coturn/coturn:latest -c /etc/turnserver/turnserver.conf
```
