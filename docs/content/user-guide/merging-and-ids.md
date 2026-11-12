+++
title = "Merging & Canonical IDs"
description = "Combine VEX feeds and generate deterministic document identifiers"
weight = 6
+++

Two operational helpers that come up when assembling VEX from more than
one source:

- `Vex::Document.merge` — union the statements of several documents into
  one, deduplicating value-equal entries.
- `Vex::Document#regenerate_id` — derive a stable `@id` from the
  document's content (go-vex's canonical hash), so a re-run on the same
  data produces the same identifier.

## Merging documents

The merged document preserves the **full history** — statements aren't
collapsed by (product, vuln). [`effective_statement`](./effective-statement)
picks the most recent ruling at lookup time, so consumers see the latest
state while auditors still have the trail. A statement that inherited its
source document's `timestamp` gets that timestamp set explicitly, so it
isn't re-dated to the merged document's. If a statement has no timestamp
and neither does its document, `merge` raises `Vex::Error` rather than
re-date it (unless you pass `timestamp: nil`).

```crystal
upstream = Vex::Document.from_file("upstream.json")
internal = Vex::Document.from_file("internal.json")

combined = Vex::Document.merge([upstream, internal],
  author: "release-eng@example.com")

combined.statements.size # union, with value-equal duplicates collapsed
combined.effective_statement("pkg:generic/app@1.0.0", "CVE-2024-555")
```

Convenience form when one document is "yours" and you're folding another
into it — keeps the receiver's identity (`@id`, `author`, `role`,
`tooling`), bumps `last_updated` to now, and increments `version`:

```crystal
updated = my_doc.merge(new_doc)
```

## Canonical document IDs

When you don't have an authoritative IRI to assign as `@id`, derive one
from the document itself:

```crystal
doc = Vex::Document.new(id: "https://example.com/vex/placeholder", author: "x")
doc.add_statement(stmt)
doc.regenerate_id
# => "https://openvex.dev/docs/public/vex-<sha256-hex>"
```

The hash is go-vex's `CanonicalHash`, byte for byte, so both libraries
mint the same `@id` for the same document. It covers the document
`timestamp`, `version`, and `author`, then each statement's vulnerability
`@id`/name/aliases, status, justification, effective timestamp, and the
`@id`/hashes/identifiers of its products and their direct subcomponents.
`last_updated`, notes, impact/action statements, and role/tooling are
excluded. `canonical_hash` / `regenerate_id` raise `Vex::Error` when the document has no
`timestamp`. go-vex's format joins raw values with `:`, so it is not
collision-proof against crafted values; it's kept as-is for interop.

Two consequences worth knowing:

- Statements are sorted by vulnerability name, then effective timestamp,
  before hashing. Statements that tie on both keep source order, so, as in
  go-vex, reordering them changes the hash.
- `merge(...)` without an explicit `id:` auto-generates a canonical ID
  from the merged document, so two services merging the same inputs with
  the same `timestamp:` and `author:` get the same `@id`. With
  `timestamp: nil` there is nothing to hash, so pass `id:` explicitly.

See [`examples/merge.cr`](https://github.com/hahwul/vex.cr/blob/main/examples/merge.cr)
for a runnable walkthrough.
