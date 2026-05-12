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
```

### Validation

Conditional-field rules from the spec are checked on demand:

```crystal
stmt = Vex::Statement.new(
  status: Vex::Status::NotAffected,
  vulnerability: Vex::Vulnerability.new(name: "CVE-2024-9999"),
)
stmt.valid?    # => false
stmt.validate  # => ["status 'not_affected' requires justification or impact_statement"]
```

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
