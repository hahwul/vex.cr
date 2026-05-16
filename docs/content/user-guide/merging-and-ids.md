+++
title = "Merging & Canonical IDs"
description = "Combine VEX feeds and generate deterministic document identifiers"
weight = 6
+++

Two operational helpers that come up when assembling VEX from more than
one source:

- `Vex::Document.merge` — union the statements of several documents into
  one, deduplicating value-equal entries.
- `Vex::Document.generate_canonical_id` — derive a stable `@id` from the
  identifying content of the statements, so a re-run on the same data
  produces the same identifier.

## Merging documents

The merged document preserves the **full history** — statements aren't
collapsed by (product, vuln). [`effective_statement`](./effective-statement)
picks the most recent ruling at lookup time, so consumers see the latest
state while auditors still have the trail.

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
`tooling`) and bumps `last_updated` to now:

```crystal
updated = my_doc.merge(new_doc)
```

## Canonical document IDs

When you don't have an authoritative IRI to assign as `@id`, derive one
from the statements themselves:

```crystal
doc = Vex::Document.new(id: "https://example.com/vex/placeholder", author: "x")
doc.add_statement(stmt)
doc.regenerate_id
# => "https://openvex.dev/docs/vex-<sha256-hex>"
```

The hash covers only fields that identify the assertion (vulnerability
name/id/aliases, status, justification, action/impact statements,
supplier, and the recursive product/subcomponent identifier tree).
Mutable bookkeeping (`status_notes`, `last_updated`, statement-level
timestamps) is excluded so equivalent updates don't churn the ID.

Two consequences worth knowing:

- Statement order doesn't matter — the canonical form sorts statements
  before hashing.
- `merge(...)` without an explicit `id:` auto-generates a canonical ID
  from the merged statements, so two services merging the same inputs
  end up with byte-identical documents.

See [`examples/merge.cr`](https://github.com/hahwul/vex.cr/blob/main/examples/merge.cr)
for a runnable walkthrough.
