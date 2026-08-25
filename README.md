# DTLS

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.2-blue.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)

A PHP implementation of [Datagram Transport Layer Security (DTLS)](https://datatracker.ietf.org/doc/html/rfc6347), designed for secure communication over UDP, especially in real-time communication protocols such as WebRTC and SRTP.

## About this fork

This is the `danog/php-rtc-dtls` fork used by MadelineProto. It targets PHP 8.2+, runs on Amp v3 fibers, and uses the pure-PHP DTLS 1.2 engine backed by phpseclib instead of OpenSSL FFI. Its handshake driver includes timer, retransmission, and packet-loss recovery fixes validated against independent DTLS implementations.

All internal Composer dependencies use their `danog/php-rtc-*` package names directly, so installing a component selects the maintained danog packages throughout the dependency graph.

## Features

- DTLS 1.2 handshake implementation
- Secure communication over UDP
- Certificate and key generation
- Integration-ready with SRTP (Secure RTP)
- Peer authentication


## Requirements

- PHP ≥ 8.2
- phpseclib 3 (installed through Composer)
- Linux environment (Windows/macOS support planned)

## Documentation

This package is part of the PHP WebRTC library. For complete documentation, examples, and API reference, visit:

[PHP WebRTC Documentation](https://github.com/danog/php-rtc-dtls)

## Credits

### Authors

- **Amin Yazdanpanah**  
  - Website: [aminyazdanpanah.com](https://www.aminyazdanpanah.com)
  - Email: [github@aminyazdanpanah.com](mailto:github@aminyazdanpanah.com)

- **Sana Moniri**  
  - GtiHub: [sanamoniri](https://github.com/sanamoniri)

## Reporting Issues

Found a bug? Please report it on our [issues](https://github.com/php-webrtc/dtls/issues).

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.
