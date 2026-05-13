+++
title = "Vex::Product & Vex::Subcomponent"
description = "Product and subcomponent components"
weight = 3
+++

Products and subcomponents share a base class, `Vex::Component`, that
captures the identification fields the OpenVEX spec requires for both.
On the wire there is no `Component` type — only `product` and
`subcomponent` shapes.

## `Vex::Component`

Base class (not used directly):

| Field         | Type                          | Wire key       |
|---------------|-------------------------------|----------------|
| `id`          | `String?`                     | `@id`          |
| `hashes`      | `Hash(String, String)?`       | `hashes`       |
| `identifiers` | `Hash(String, String)?`       | `identifiers`  |

The spec puts `supplier` at the statement level (`Vex::Statement#supplier`),
not on `Component`. vex.cr does not emit `supplier` from a `Component`
even if a legacy input document carried it there.

### Methods

- **`matches?(identifier : String) : Bool`** — returns `true` if
  `@id` equals `identifier` or any `identifiers` value equals it.
  This powers product lookups in `Document#effective_statement`.

## `Vex::Product`

Inherits every field from `Vex::Component` and adds:

| Field           | Type                       | Wire key        |
|-----------------|----------------------------|-----------------|
| `subcomponents` | `Array(Subcomponent)?`     | `subcomponents` |

### Constructor

```crystal
Vex::Product.new(
  id : String? = nil,
  identifiers : Hash(String, String)? = nil,
  hashes : Hash(String, String)? = nil,
  subcomponents : Array(Vex::Subcomponent)? = nil,
)
```

### Examples

```crystal
# Identify by purl alone:
Vex::Product.new(id: "pkg:generic/example@1.0.0")

# Identify by an OCI digest and a purl alias, with one subcomponent:
Vex::Product.new(
  id: "pkg:oci/example@sha256:...",
  identifiers: {"purl" => "pkg:oci/example"},
  hashes: {"sha-256" => "..."},
  subcomponents: [
    Vex::Subcomponent.new(id: "pkg:generic/libfoo@1.2.3"),
  ],
)
```

## `Vex::Subcomponent`

A plain subclass of `Vex::Component` with no extra fields — same
identification surface as a product, but appears nested under a
product on the wire.

```crystal
Vex::Subcomponent.new(id: "pkg:generic/libfoo@1.2.3")
```
