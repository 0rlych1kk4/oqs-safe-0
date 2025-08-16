# misra-ci

[![CI](https://img.shields.io/github/actions/workflow/status/0rlych1kk4/misra-ci/ci.yml?label=CI)](../../actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](https://www.rust-lang.org)
[![Reports](https://img.shields.io/badge/outputs-JUnit%20%7C%20HTML%20%7C%20SARIF-success)](#outputs)

**MISRA/ISO 26262 CI helper** — a Rust CLI + GitHub Action that scans C/C++ sources, emits **JUnit**, **HTML**, and **SARIF** reports, and can **gate** builds by severity thresholds.

-  Ideal for **embedded/AUTOSAR/ASPICE** pipelines
-  Portable baseline (no licensed tools required)
-  Extensible (wire in `cppcheck`/vendor tools later)
-  Clear pass/fail **gates** to block non-compliant code

---
##  Features

- Recursively scans `.c/.h/.cpp/.hpp`
- Configurable **ruleset** (YAML) with simple heuristics
- Standard **outputs**: JUnit XML, HTML, SARIF 2.1.0
- **Gate** policy (e.g., `critical:0,high:5,medium:20,low:100`)
- Deterministic + fast builds (Rust)

> Note: Heuristics are intentionally minimal so the tool runs anywhere.
> You can extend the YAML or integrate stronger engines later.

---
## Quick start (CLI)

```bash
cargo run -p misra_cli --   --source ./examples/c_project   --rules ./rulesets/misra-c-2012.yaml   --out dir:target/misra-ci   --gate "critical:0,high:5,medium:20,low:100"
```

Outputs appear in `target/misra-ci/`:
- `report.junit.xml`
- `report.html`
- `report.sarif.json`

## Quick start (GitHub Action)
After you push and tag (e.g., `v0`), use:

```yaml
name: MISRA CI
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 0rlych1kk4/misra-ci@v0  # tag this repo as v0
        with:
          source: ./examples/c_project
          rules:  ./rulesets/misra-c-2012.yaml
          gate:   "critical:0,high:5,medium:20,low:100"
      - uses: actions/upload-artifact@v4
        with:
          name: misra-reports
          path: target/misra-ci
```
---
## Configuration
Ruleset — rulesets/misra-c-2012.yaml
```yaml
severities:
  critical: ["rule-21.6"]
  high:     ["rule-15.1"]
  medium:   ["rule-2.2"]
  low:      ["rule-10.1", "rule-13.4"]

heuristics:
  - pattern: "\\bgets\\s*\\("
    rule: "rule-21.6"
    severity: "critical"
  - pattern: "\\bgoto\\b"
    rule: "rule-15.1"
    severity: "high"
  - pattern: "//"
    rule: "rule-2.2"
    severity: "medium"
```
---

## Contributing
- cargo fmt, cargo clippy before PRs
- Add tests for new rules/parsers
- Update docs when behavior changes
---
## Roadmap
- Optional --use-cppcheck integration (XML parsing → severity map)
- More heuristics + categories
- Ignore patterns (--ignore, .misra-ci-ignore)
- Per-directory rules overrides

## License
- Apache-2.0 © 2025 Orly Trajano

---
