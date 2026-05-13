+++
title = "vex.cr"
description = "A Crystal implementation of the OpenVEX (Vulnerability Exploitability eXchange) specification"
+++

A Crystal library that produces, consumes, and validates
[OpenVEX v0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
documents. VEX is a machine-readable way for software producers to assert
whether a given product is affected by a known vulnerability, so consumers can
avoid chasing false positives from SBOM-based vulnerability scanners.

## Quick Links

- **[Getting Started](/user-guide/getting-started/)** — install and write your first document
- **[Producing Documents](/user-guide/producing/)** — `Vex::Document`, statements, statuses
- **[Consuming Documents](/user-guide/consuming/)** — parse JSON, iterate statements
- **[Validation](/user-guide/validation/)** — conditional-field rules from the spec
- **[Effective Statement](/user-guide/effective-statement/)** — find the most recent ruling
- **[API Reference](/api-reference/document/)** — all classes and methods

## Highlights

- Round-trip JSON: every `Vex::*` type ships `JSON::Serializable`, so
  `Document.from_json(...).to_json` reproduces wire-compatible OpenVEX.
- UTC-normalized timestamps with the trailing `Z` the spec mandates.
- Tolerant parsing: required-but-missing fields surface through
  `validate` / `valid?` instead of raising at parse time — matching the
  behaviour of the reference `go-vex` implementation.
- `effective_statement(product, vulnerability)` mirrors the OpenVEX
  "most recent ruling wins" semantics, including alias lookup.
- Value equality and `hash` — documents and statements work as `Set` /
  `Hash` keys.
- UTF-8 BOM tolerance on `Document.from_file` for Windows-emitted JSON.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  vex:
    github: hahwul/vex.cr
```

Then run:

```bash
shards install
```

## Quick Example

```crystal
require "vex"

doc = Vex::Document.new(
  id: "https://example.com/vex/2025-001",
  author: "security@example.com",
)

doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::NotAffected,
    vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0001"),
    products: [Vex::Product.new(id: "pkg:generic/example@1.0.0")],
    justification: Vex::Justification::VulnerableCodeNotInExecutePath,
  ),
)

puts doc.to_json_pretty
```
