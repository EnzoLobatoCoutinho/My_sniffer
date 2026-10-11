# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-10-11

### Added

- Behavioral analysis engine (Strategy list): `AnalysisEngine` runs every
  captured packet through independent `IAnalyzer` strategies and
  aggregates their alerts.
- `RateSpikeAnalyzer` - flags a source IP sending more packets than a
  threshold within a sliding time window.
- `ForeignIpAnalyzer` - flags outbound connections to a public IP not on
  an allow-list (private/loopback ranges always exempt), alerting once
  per unique destination. New `--allow-ip` CLI flag to pre-approve known
  foreign IPs.
- `PortProtocolAnalyzer` - flags traffic on a well-known port (80, 443)
  whose payload doesn't match the protocol that port is supposed to
  carry, a heuristic for tunneling/protocol smuggling.
- `BeaconAnalyzer` - flags a (src IP, dst IP, dst port) flow whose
  packets arrive at suspiciously regular intervals, a signature of
  automated periodic callbacks ("beaconing").
- `scripts/simulate_beacon.sh` and `scripts/simulate_spike.sh`, UDP-based
  traffic generators for manually validating the analyzers against real
  capture.

### Fixed

- The capture callback in `main.cpp` never called
  `PacketBuilder::setTimestamp()`, leaving every packet at the Unix
  epoch and silently breaking every time-based analyzer
  (`RateSpikeAnalyzer`, `BeaconAnalyzer`).

## [0.2.0] - 2026-09-22

### Added

- Packet filtering (Composite pattern): `IFilter`, leaf filters (`IpFilter`,
  `PortFilter`, `ProtocolFilter`), and combinators (`AndFilter`, `OrFilter`,
  `NotFilter`) that nest into arbitrary rule expressions.
- `bytes::parseIpv4`, the hand-rolled counterpart to `ipv4ToString` (no
  `inet_pton`/`inet_aton`), parsing `"a.b.c.d"` into the same
  representation used everywhere else in the project.
- CLI filter flags on `my_sniffer` (`--port`, `--ip`, `--protocol`,
  combinable with an implicit AND), with input validation that reports
  errors on stderr instead of crashing.
- Platform install scripts (`scripts/install.sh`, `scripts/install.ps1`)
  that build, install, and (Linux) grant `CAP_NET_RAW` via `setcap` so the
  binary can run without `sudo` afterwards.

## [0.1.0] - 2026-09-21

### Added

- Core packet model: immutable `Packet`, mutable `PacketBuilder`, and an
  `EventBus` decoupling capture/parsing from anything that consumes
  packets (storage, analysis, a future GUI/TUI).
- Hand-rolled byte helpers (`bytes_utils`) for big-endian field reads and
  MAC/IPv4 formatting, with no reliance on system byte-order conversion
  functions or any networking/parsing library.
- Protocol parsing chain (Chain of Responsibility): `EthernetHandler`,
  `Ipv4Handler`, `TcpHandler`, `UdpHandler`, covering the mandatory
  minimum protocol set (Ethernet, IPv4, TCP, UDP).
- Raw packet capture on Linux (`CaptureLinux`) via `AF_PACKET`/`SOCK_RAW`.
- CLI entry point wiring capture -> parsing chain -> event bus -> live
  packet display.
- CMake `install()` target.
- README documentation covering build, run, install, and the elevated
  privileges required for raw capture (`CAP_NET_RAW`/root on Linux,
  Npcap + Administrator on Windows).

[Unreleased]: https://github.com/EnzoLobatoCoutinho/My_sniffer/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/EnzoLobatoCoutinho/My_sniffer/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/EnzoLobatoCoutinho/My_sniffer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EnzoLobatoCoutinho/My_sniffer/releases/tag/v0.1.0
