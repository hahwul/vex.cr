+++
title = "Consuming Documents"
description = "Parse OpenVEX JSON and iterate statements"
weight = 3
+++

`Vex::Document` parses any OpenVEX v0.2.0 JSON document with
`Document.from_json` or `Document.from_file`.

## Parsing from JSON

```crystal
require "vex"

doc = Vex::Document.from_json(File.read("vex.json"))

doc.statements.each do |stmt|
  vuln    = stmt.vulnerability.try(&.name)
  product = stmt.products.try(&.first?.try(&.id))
  puts "#{vuln} on #{product}: #{stmt.status}"
end
```

`stmt.status` is a `Vex::Status` enum, so `puts` prints the wire string
(`not_affected`, `affected`, `fixed`, `under_investigation`) via the
custom `to_s`.

## Parsing from a file

`Document.from_file` reads the file and strips a leading UTF-8 BOM if
present — Windows-emitted JSON often carries one, and Crystal's parser
is strict about leading whitespace and BOMs.

```crystal
doc = Vex::Document.from_file("vex.json")
```

## Tolerant parsing

vex.cr matches the reference `go-vex` implementation: required-but-missing
top-level fields (`@context`, `@id`, `author`, `version`) do **not** raise
at parse time. They default to empty strings / `0` and are surfaced by
the validator:

```crystal
doc = Vex::Document.from_json(%({"statements": []}))
doc.valid?   # => false
doc.validate # => ["@context must not be empty", "@id must not be empty", ...]
```

See [Validation](/user-guide/validation/) for the full list of rules.

## Round-trip

Every type round-trips through JSON cleanly:

```crystal
raw  = File.read("vex.json")
doc  = Vex::Document.from_json(raw)
raw2 = doc.to_json_pretty
# raw2 carries the same data; key order follows the declaration order
# in `Vex::Document`.
```

Fields that were `nil` on parse stay omitted on serialize, so a
round-trip will not introduce noise like `"role": null`.
