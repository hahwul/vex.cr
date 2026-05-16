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

| Field           | Type                          | Wire key        |
|-----------------|-------------------------------|-----------------|
| `id`            | `String?`                     | `@id`           |
| `hashes`        | `Hash(String, String)?`       | `hashes`        |
| `identifiers`   | `Hash(String, String)?`       | `identifiers`   |
| `subcomponents` | `Array(Subcomponent)?`        | `subcomponents` |

The spec lists `subcomponents` on Component, so it lives on the base
class and Subcomponent itself can nest further subcomponents.

The spec puts `supplier` at the statement level (`Vex::Statement#supplier`),
not on `Component`. vex.cr does not emit `supplier` from a `Component`
even if a legacy input document carried it there.

### Methods

- **`matches?(identifier : String) : Bool`** — returns `true` if
  `@id` equals `identifier`, any `identifiers` value equals it, or any
  (recursive) subcomponent matches. This powers product lookups in
  `Document#effective_statement` and `Document#find_statements`.

## `Vex::Product`

A plain subclass of `Vex::Component` with no extra fields — Product is
distinguished from Subcomponent by *where* it appears on the wire
(`statements[].products[]`), not by structure.

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
product on the wire. Because `subcomponents` lives on `Component`,
a Subcomponent can itself nest further subcomponents (e.g. a
container image embedding a library that embeds a vendored
dependency).

```crystal
Vex::Subcomponent.new(
  id: "pkg:generic/libfoo@1.2.3",
  subcomponents: [
    Vex::Subcomponent.new(id: "pkg:generic/vendored-dep@0.1.0"),
  ],
)
```
