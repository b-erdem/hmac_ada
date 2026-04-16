# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-16

Initial public release.

### Added
- SHA-256 implementation in Ada 2022 (FIPS 180-4), `pragma SPARK_Mode (On)`,
  streaming (Initialize / Update / Finalize) and one-shot (`Compute`) API,
  proved clean at Level 2.
- HMAC-SHA-256 per RFC 2104 / RFC 4231 (`HMAC_SHA256`),
  `pragma SPARK_Mode (On)`, streaming and one-shot API, proved clean at
  Level 2.
- Generic `HMAC` package parameterised by the underlying hash function.
  `SPARK_Mode (Off)` because generic formal subprograms carry no
  contracts that gnatprove can reason about; concrete instantiations
  (e.g. `HMAC_SHA256`) recover full proof.
- Constant-time digest comparison (`Equal`) via XOR accumulation with
  `pragma No_Inline` to defeat early-exit timing optimisation.
- Zero-on-drop discipline for key material and intermediate state
  (`IPad_Key`, `OPad_Key`, `K0`, inner digest, SHA-256 message schedule
  and working variables) paired with `pragma Inspection_Point` to stop
  dead-store elimination.
- `Byte_Array` subtype alias for the public API so downstream code need
  not import `System.Storage_Elements` just to call the library.
- `System.Storage_Elements.Storage_Array` for all byte-sequence I/O;
  no dependency on `Ada.Streams`, safe for Light and ZFP runtimes.
- 26 unit tests covering FIPS 180-4 SHA-256 vectors, all seven RFC 4231
  HMAC-SHA-256 vectors, streaming and edge cases, plus constant-time
  `Equal` validation.
- GitHub Actions CI on Ubuntu and macOS running build, tests, and
  `gnatprove --level=2` with automated regression check that no
  unproved obligations creep in.
- Apache-2.0 licence.

### Security
- HMAC-SHA-256: 174/174 SPARK checks proved, zero `pragma Assume`,
  zero justified checks, zero warnings at Level 2.
- No heap allocation; stack-bounded throughout.
- No `Unchecked_Conversion`, `Unchecked_Deallocation`, `pragma Suppress`,
  or `System.Address` usage in the core crypto packages.

[Unreleased]: https://github.com/b-erdem/hmac_ada/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/b-erdem/hmac_ada/releases/tag/v0.1.0
