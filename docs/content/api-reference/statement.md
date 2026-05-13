+++
title = "Vex::Statement"
description = "A single VEX statement"
weight = 2
+++

`Vex::Statement` is one ruling — a status applied to a (product,
vulnerability) pair, plus the conditional fields the spec requires for
that status.

## Fields

| Field                          | Type                | Wire key                     |
|--------------------------------|---------------------|------------------------------|
| `id`                           | `String?`           | `@id`                        |
| `version`                      | `Int32?`            | `version`                    |
| `vulnerability`                | `Vulnerability?`    | `vulnerability`              |
| `timestamp`                    | `Time?`             | `timestamp`                  |
| `last_updated`                 | `Time?`             | `last_updated`               |
| `products`                     | `Array(Product)?`   | `products`                   |
| `status`                       | `Status`            | `status`                     |
| `status_notes`                 | `String?`           | `status_notes`               |
| `justification`                | `Justification?`    | `justification`              |
| `impact_statement`             | `String?`           | `impact_statement`           |
| `action_statement`             | `String?`           | `action_statement`           |
| `action_statement_timestamp`   | `Time?`             | `action_statement_timestamp` |
| `supplier`                     | `String?`           | `supplier`                   |

`status` is the only structurally required field at the type level —
the rest are optional and validated by their relationship to `status`.

## Constructor

```crystal
Vex::Statement.new(
  status : Vex::Status,
  vulnerability : Vex::Vulnerability? = nil,
  products : Array(Vex::Product)? = nil,
  id : String? = nil,
  version : Int32? = nil,
  timestamp : Time? = nil,
  last_updated : Time? = nil,
  status_notes : String? = nil,
  justification : Vex::Justification? = nil,
  impact_statement : String? = nil,
  action_statement : String? = nil,
  action_statement_timestamp : Time? = nil,
  supplier : String? = nil,
)
```

## Methods

### `validate : Array(String)`

Returns spec-violation errors:

- `not_affected` without `justification` or `impact_statement`
- `not_affected` with `action_statement` set
- `affected` without `action_statement`
- `affected` with `justification` or `impact_statement` set
- any product missing `@id`, `identifiers`, and `hashes`

### `valid? : Bool`

Shortcut for `validate.empty?`.

### Equality

`Vex::Statement` implements value equality and `hash` over every
field, so statements work as `Set` / `Hash` keys.
