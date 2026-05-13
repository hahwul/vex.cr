+++
title = "Validation"
description = "Conditional-field rules from the OpenVEX v0.2.0 spec"
weight = 4
+++

vex.cr validates documents on demand. Parsing never raises for missing
required fields — instead, `valid?` and `validate` surface all spec
violations as plain strings.

## Document-level rules

`Document#validate` returns an array of errors covering both the
document and every contained statement.

```crystal
doc = Vex::Document.from_json(%({"statements": []}))
doc.valid?   # => false
doc.validate
# => ["@context must not be empty",
#     "@id must not be empty",
#     "author must not be empty",
#     "version must be >= 1"]
```

The validator also enforces the spec rule that **statement `@id` values
must be unique within a document**:

```crystal
doc.validate
# => ["statements[1]: duplicate @id \"urn:example:1\""]
```

## Statement-level rules

`Statement#validate` covers the conditional-field rules from
[§4 of the spec](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-labels):

| Status                | Required                                    | Forbidden                                |
|-----------------------|---------------------------------------------|------------------------------------------|
| `not_affected`        | `justification` or `impact_statement`       | `action_statement`                       |
| `affected`            | `action_statement`                          | `justification`, `impact_statement`      |
| `fixed`               | (no extra)                                  | (no extra)                               |
| `under_investigation` | (no extra)                                  | (no extra)                               |

```crystal
stmt = Vex::Statement.new(
  status: Vex::Status::NotAffected,
  vulnerability: Vex::Vulnerability.new(name: "CVE-2024-9999"),
)
stmt.valid?
# => false
stmt.validate
# => ["status 'not_affected' requires justification or impact_statement"]
```

## Product identifiability

Each product must be identifiable by `@id`, an `identifiers` entry, or
`hashes`:

```crystal
stmt = Vex::Statement.new(
  status: Vex::Status::Fixed,
  products: [Vex::Product.new],   # nothing set
)
stmt.validate
# => ["products[0] has no @id, identifiers, or hashes"]
```

## Warnings (SHOULD, not MUST)

`Document#warnings` returns non-fatal advisories that the spec marks
as SHOULD rather than MUST. They do not affect `valid?`.

```crystal
doc.warnings
# => ["statements[0].products[0]: hash algorithm \"sha-128\" is not in Appendix A",
#     "statements[0].products[0]: identifier type \"oci\" is not in Appendix B",
#     "@context \"https://example.com/ctx\" is not an openvex.dev namespace URL"]
```

Currently covers:

- `@context` URLs that don't match `https://openvex.dev/ns/v[version]`
- Hash algorithm keys outside [Appendix A](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#appendix-a-hash-names-table)
  (`md5`, `sha1`, `sha-256`, `sha-384`, `sha-512`, `sha3-{224,256,384,512}`, `blake2{s-256,b-256,b-512}`)
- Identifier type keys outside [Appendix B](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#appendix-b-software-identifier-types-table)
  (`purl`, `cpe22`, `cpe23`)

Strict tooling can treat `doc.warnings.any?` as a failure under its
own policy.

## Validating before serializing

A common pattern is to validate before writing to disk and fail fast on
authoring errors:

```crystal
errors = doc.validate
if errors.empty?
  doc.write("vex.json")
else
  STDERR.puts "refusing to write invalid VEX document:"
  errors.each { |e| STDERR.puts "  - #{e}" }
  exit 1
end
```
