# vex.cr

[OpenVEX](https://github.com/openvex/spec) (Vulnerability Exploitability eXchange)
implementation for Crystal, conforming to the
[OpenVEX v0.2.0 specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).

VEX is a machine-readable way for software producers to assert whether a given
product is affected by a known vulnerability, so consumers can avoid chasing
false positives from SBOM-based vulnerability scanners.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  vex:
    github: hahwul/vex.cr
```

Then run `shards install`.

## Usage

### Producing a document

```crystal
require "vex"

doc = Vex::Document.new(
  id: "https://example.com/vex/2025-001",
  author: "security@example.com",
  role: "Document Creator",
)

doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::NotAffected,
    vulnerability: Vex::Vulnerability.new(
      name: "CVE-2024-0001",
      aliases: ["GHSA-xxxx-yyyy-zzzz"],
    ),
    products: [
      Vex::Product.new(id: "pkg:generic/example@1.0.0"),
    ],
    justification: Vex::Justification::VulnerableCodeNotInExecutePath,
  ),
)

puts doc.to_json_pretty
```

### Consuming a document

```crystal
doc = Vex::Document.from_json(File.read("vex.json"))

doc.statements.each do |stmt|
  vuln_name = stmt.vulnerability.try(&.name)
  puts "#{vuln_name}: #{stmt.status}"
end

# Find the most recent ruling for a (product, vuln) pair:
eff = doc.effective_statement("pkg:generic/example@1.0.0", "CVE-2024-0001")

# Or the full history of statements matching that pair (source order):
history = doc.find_statements("pkg:generic/example@1.0.0", "CVE-2024-0001")
```

Product and vulnerability lookups match on `@id`, on any value in
`identifiers`, and on a vulnerability `name` or any entry in `aliases` —
the same identifier resolution applies to both helpers.

### Validation

Conditional-field rules from the spec are checked on demand. `validate`
surfaces MUST violations; `warnings` surfaces SHOULD advisories.

```crystal
stmt = Vex::Statement.new(
  status: Vex::Status::NotAffected,
  vulnerability: Vex::Vulnerability.new(name: "CVE-2024-9999"),
)
stmt.valid?    # => false
stmt.validate  # => ["status 'not_affected' requires justification or impact_statement"]
```

```crystal
doc = Vex::Document.new(
  id: "https://example.com/vex/x",
  author: "security@example.com",
)
doc.add_statement(Vex::Statement.new(
  status: Vex::Status::Fixed,
  vulnerability: Vex::Vulnerability.new(name: "CVE-X", id: "CVE-X"),
  products: [Vex::Product.new(id: "pkg:x")],
  supplier: "Acme Corp",
))
doc.warnings
# => [
#      "statements[0]: supplier \"Acme Corp\" is not an IRI (missing scheme)",
#      "statements[0].vulnerability: @id \"CVE-X\" is not an IRI (missing scheme)",
#    ]
```

See [`examples/validation.cr`](examples/validation.cr) for a runnable
walkthrough of `validate`, `warnings`, `find_statements`, and
`effective_statement`.

### Canonical document IDs

When you don't have an authoritative IRI to assign as `@id`, derive one
deterministically from the statements:

```crystal
doc = Vex::Document.new(id: "https://example.com/vex/placeholder", author: "x")
doc.add_statement(Vex::Statement.new(
  status: Vex::Status::Fixed,
  vulnerability: Vex::Vulnerability.new(name: "CVE-2024-9"),
  products: [Vex::Product.new(id: "pkg:generic/app@1")],
))
doc.regenerate_id
# => "https://openvex.dev/docs/vex-<sha256-hex>"
```

The hash covers only fields that identify the assertion (vulnerability
name/id/aliases, status, justification, action/impact statements, supplier,
and the full product/subcomponent identifier tree). Mutable bookkeeping
fields (`status_notes`, `last_updated`, statement timestamps) are excluded
so equivalent updates don't churn the document ID.

### Merging documents

Combine VEX feeds from multiple sources — the merged document carries the
full history, and `effective_statement` selects the most recent ruling at
lookup time.

```crystal
combined = Vex::Document.merge([upstream_doc, internal_doc], author: "ops")
# Or, keeping the receiver's identity:
updated = my_doc.merge(new_doc)
```

Value-equal statements are deduplicated; (product, vuln) overlap is
preserved so the audit trail isn't lost.

### Supported types

| Type | OpenVEX field |
| --- | --- |
| `Vex::Document` | top-level VEX document |
| `Vex::Statement` | individual statement |
| `Vex::Product` / `Vex::Subcomponent` | product/subcomponent components |
| `Vex::Vulnerability` | vulnerability struct |
| `Vex::Status` | `not_affected`, `affected`, `fixed`, `under_investigation` |
| `Vex::Justification` | the five spec-defined justification labels |

## Development

```sh
crystal spec
```

## Contributing

1. Fork it (<https://github.com/hahwul/vex.cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## License

MIT. See [LICENSE](LICENSE).
