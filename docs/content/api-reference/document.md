+++
title = "Vex::Document"
description = "Top-level OpenVEX document"
weight = 1
+++

`Vex::Document` is the top-level OpenVEX container. It holds metadata
(`@context`, `@id`, `author`, `version`, `timestamp`, ...) plus the
list of `Vex::Statement` entries.

## Fields

| Field           | Type                  | Wire key       | Required |
|-----------------|-----------------------|----------------|----------|
| `context`       | `String`              | `@context`     | yes      |
| `id`            | `String`              | `@id`          | yes      |
| `author`        | `String`              | `author`       | yes      |
| `role`          | `String?`             | `role`         | no       |
| `timestamp`     | `Time?`               | `timestamp`    | no       |
| `last_updated`  | `Time?`               | `last_updated` | no       |
| `version`       | `Int32`               | `version`      | yes (>=1)|
| `tooling`       | `String?`             | `tooling`      | no       |
| `supplier`      | `String?`             | `supplier`     | no       |
| `statements`    | `Array(Statement)`    | `statements`   | yes      |

Required fields default to empty strings / `0` rather than raising at
parse time — see [Validation](/user-guide/validation/).

## Constructors

```crystal
Vex::Document.new(
  id : String,
  author : String = Vex::DEFAULT_AUTHOR,
  statements : Array(Statement) = [] of Statement,
  version : Int32 = 1,
  context : String = Vex::CONTEXT,
  timestamp : Time? = Time.utc,
  last_updated : Time? = nil,
  role : String? = nil,
  tooling : String? = nil,
  supplier : String? = nil,
)
```

## Methods

### `add_statement(statement : Statement) : self`

Appends a statement to `statements` and returns `self` for chaining.

### `validate : Array(String)`

Returns a list of validation errors covering both document-level
fields and every contained statement. Empty array means valid.

### `valid? : Bool`

Shortcut for `validate.empty?`.

### `effective_statement(product, vulnerability) : Statement?`

Returns the most recent statement that covers both the given product
identifier (matched against `@id` and every `identifiers` value) and
the given vulnerability identifier (matched against `@id`, `name`, and
`aliases`). See [Effective Statement](/user-guide/effective-statement/).

### `to_json_pretty : String`

Returns a 2-space indented JSON serialization. Use `to_json` for
compact output.

### `Document.from_file(path : String) : Document`

Reads JSON from disk, stripping a leading UTF-8 BOM if present.

### `write(path : String) : Nil`

Writes the document to disk as pretty JSON.

### Equality

`Vex::Document` implements value equality and `hash` over all fields,
so documents work as `Set` / `Hash` keys.
