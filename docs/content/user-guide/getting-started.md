+++
title = "Getting Started"
description = "Install vex.cr and emit your first OpenVEX document"
weight = 1
+++

## Prerequisites

| Requirement | Version    |
|-------------|------------|
| Crystal     | >= 1.20.1  |

vex.cr is pure Crystal with no native dependencies — it runs anywhere Crystal
does.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  vex:
    github: hahwul/vex.cr
```

Then install:

```bash
shards install
```

## Your First Program

Create `hello.cr`:

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

puts doc.valid?         # => true
puts doc.to_json_pretty
```

Run it:

```bash
crystal run hello.cr
```

You should see a valid OpenVEX v0.2.0 document on stdout, with the
`@context`, `@id`, `author`, `version`, `timestamp`, and `statements`
fields populated.

## Next Steps

- **[Producing Documents](/user-guide/producing/)** — every constructor argument explained
- **[Consuming Documents](/user-guide/consuming/)** — parse JSON, iterate statements
- **[Validation](/user-guide/validation/)** — make sure your document is spec-conformant
- **[Effective Statement](/user-guide/effective-statement/)** — query the most recent ruling
