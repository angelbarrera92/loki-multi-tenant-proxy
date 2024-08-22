# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Refactor configuration so that `target server` or `keep-org-id` are now configured via config instead of via a cli flag.

## [0.5.0] - 2024-02-23

### Changed

- Renamed project to `grafana-multi-tenant-proxy`
- Renamed parameter `loki-server` to `target-server`

## [0.4.0] - 2024-02-19

### Added

- Allow reload of config via the `/-/reload` endpoint.

## [0.3.0] - 2024-02-08

### Added

- Add OAuth token support for 'read' user.

## [0.2.0] - 2023-12-11

### Changed:

- Bump github.com/urfave/cli from 1.22.10 to v2.26.0
- Use zap as logger and log status code.

## [0.1.0] - 2022-10-11

## [0.0.0] - 2022-10-11

- changed: add '--keep-orgid' option
- changed: image renamed to loki-multi-tenant-proxy-gs
- changed: Setup CI
- Bump github.com/urfave/cli from 1.21.0 to 1.22.10
- Bump gopkg.in/yaml.v2 from 2.2.2 to 2.4.0

[Unreleased]: https://github.com/giantswarm/grafana-multi-tenant-proxy/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/giantswarm/grafana-multi-tenant-proxy/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/giantswarm/loki-multi-tenant-proxy/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/giantswarm/loki-multi-tenant-proxy/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/giantswarm/loki-multi-tenant-proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/giantswarm/loki-multi-tenant-proxy/compare/v0.0.0...v0.1.0
[0.0.0]: https://github.com/giantswarm/loki-multi-tenant-proxy/releases/tag/v0.0.0
