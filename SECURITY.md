# Security Policy

## Supported Versions

Only the latest released minor version receives security fixes.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |
| < 0.1   | no        |

## Reporting a Vulnerability

Please report suspected security issues privately by emailing
**baris@erdem.dev** with `[hmac_ada security]` in the subject line.

If possible, include:
- a clear description of the issue,
- a minimal reproduction (input, call sequence, expected vs. actual
  behaviour),
- the commit / tag you tested against,
- your assessment of impact and any suggested mitigation.

Please do not open a public GitHub issue for security reports.

### Response timeline

- Acknowledgement: within 7 days.
- Initial assessment: within 14 days.
- Fix + coordinated disclosure: target 90 days, sooner for high-severity
  issues. If a fix requires a longer embargo we will coordinate a date
  with the reporter.

## Security Properties and Scope

`hmac_ada` provides HMAC-SHA-256 and SHA-256 in Ada 2022 with SPARK
proofs. The crate is intended for use in safety-critical and
security-sensitive systems. The current security posture is:

- **Functional correctness**: HMAC-SHA-256 and SHA-256 are proved
  clean at SPARK Level 2 (174 verification conditions, zero
  `pragma Assume`, zero justified checks). Runtime safety (no
  buffer overflows, integer overflow, uninitialised reads, or
  array-index violations) follows from the proofs.
- **Constant-time tag comparison**: `HMAC_SHA256.Equal` compares
  digests via XOR accumulation with `pragma No_Inline`. This gives
  practical constant-time behaviour under GNAT/GCC but is not a
  formally verified constant-time guarantee (which would require
  target-specific analysis of the emitted machine code).
- **Key and state scrubbing**: Sensitive locals (`IPad_Key`,
  `OPad_Key`, `K0`, SHA-256 working state) are zeroed with
  `pragma Inspection_Point` to defeat dead-store elimination.
  Applications that load keys from external storage should clear
  their caller-side copies with the same care.
- **No side-channel claims beyond the above**: the library makes no
  claim about cache timing, power side-channels, or fault-injection
  resistance. If you need any of these, additional review is required.

## Known Issues / Limitations

None known at v0.1.0. This section will be updated as issues are
reported.

## Hardening Recommendations

- Build with `-gnata` (or `pragma Assertion_Policy (Check)`) if you are
  not using SPARK proof to verify preconditions statically, so that
  contract violations become runtime errors rather than undefined
  behaviour.
- Build with `-O2 -fstack-protector-strong` (or equivalent) and keep
  PIE / NX enabled in your toolchain.
- Do not log computed tags or key material.
