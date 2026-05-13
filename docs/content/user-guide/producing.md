+++
title = "Producing Documents"
description = "Build OpenVEX documents with Vex::Document and Vex::Statement"
weight = 2
+++

A VEX document is a top-level `Vex::Document` containing one or more
`Vex::Statement` entries. Each statement asserts the status of a
vulnerability against one or more products.

## Building a document

```crystal
require "vex"

doc = Vex::Document.new(
  id: "https://example.com/vex/2025-001",
  author: "security@example.com",
  role: "Document Creator",
  tooling: "vex.cr/#{Vex::VERSION}",
)
```

The constructor defaults `@context` to the OpenVEX v0.2.0 namespace,
`version` to `1`, and `timestamp` to `Time.utc`. Optional fields
(`role`, `tooling`, `supplier`, `last_updated`) are omitted from JSON
unless set.

## Adding statements

Each statement carries the status itself plus the conditional fields the
spec requires for that status.

### `not_affected`

`not_affected` requires either `justification` or `impact_statement`:

```crystal
doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::NotAffected,
    vulnerability: Vex::Vulnerability.new(
      name: "CVE-2024-0001",
      aliases: ["GHSA-aaaa-bbbb-cccc"],
    ),
    products: [Vex::Product.new(id: "pkg:generic/example@1.0.0")],
    justification: Vex::Justification::VulnerableCodeNotInExecutePath,
  ),
)
```

### `affected`

`affected` requires `action_statement`:

```crystal
doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::Affected,
    vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0002"),
    products: [Vex::Product.new(id: "pkg:generic/example@1.0.0")],
    action_statement: "Upgrade to 1.1.0 or later.",
  ),
)
```

### `fixed` and `under_investigation`

These statuses have no extra conditional fields:

```crystal
doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::Fixed,
    vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0003"),
    products: [Vex::Product.new(id: "pkg:generic/example@1.1.0")],
  ),
)
```

## Serializing

```crystal
puts doc.to_json          # compact
puts doc.to_json_pretty   # 2-space indented
doc.write("vex.json")     # writes pretty JSON to disk
```

Timestamps are normalized to UTC and serialized with a trailing `Z`,
matching the OpenVEX spec's required format.

## Products and subcomponents

`Vex::Product` carries `@id`, `identifiers`, `hashes`, `supplier`, and
optional `subcomponents` (an array of `Vex::Subcomponent`). At least one
of `@id`, `identifiers`, or `hashes` must be present for the product to
be identifiable — `validate` will flag products that have none.

```crystal
Vex::Product.new(
  id: "pkg:oci/example@sha256:...",
  identifiers: {"purl" => "pkg:oci/example"},
  hashes: {"sha-256" => "..."},
  subcomponents: [
    Vex::Subcomponent.new(id: "pkg:generic/libfoo@1.2.3"),
  ],
)
```
