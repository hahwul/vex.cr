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
| `statements`    | `Array(Statement)`    | `statements`   | yes      |

The OpenVEX spec removed `supplier` from the document level in its
2023-06-01 revision (it now lives on `Vex::Statement`). vex.cr follows
the current spec and does not emit `supplier` at the document level
even if a legacy input document carries it — see `Vex::Statement#supplier`.

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

### `effective_timestamp_for(stmt : Statement) : Time?`

Returns the effective timestamp for a contained statement, following
the spec's inheritance flow: a statement-level `timestamp` overrides
the document-level `timestamp`. Returns `nil` only when neither is set
— which `validate` flags as an invalid document.

### `effective_products_for(stmt : Statement) : Array(Product)?`

Returns the effective products for a contained statement. Standalone
OpenVEX has no encapsulating document, so this is currently just the
statement's `products` field — exposed as a helper for symmetry with
`effective_timestamp_for`.

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
