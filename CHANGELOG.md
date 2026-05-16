# Changelog

## Unreleased

### Added
- `Document#find_statements(product, vuln)` returns every matching statement
  in source order (audit/history use case). `effective_statement` delegates
  to it, so alias and identifier resolution stay consistent across both.
- `Component#identified?` predicate (true when `@id`, non-empty
  `identifiers`, or non-empty `hashes` is present).
- `Vulnerability#warnings` surfaces spec advisories (currently: non-IRI
  `@id`).
- `Vex.iri_like?` helper — pragmatic scheme-presence check used across the
  warnings chain.
- `examples/validation.cr` walks `validate`, `warnings`, `find_statements`,
  and `effective_statement` end-to-end.
- Nested subcomponents: the spec lists `subcomponents` on Component, so a
  Subcomponent can itself nest further subcomponents. Validation and
  warnings now recurse through the tree, reporting the full bracketed
  index path (e.g. `products[0].subcomponents[1].subcomponents[0]`).
- `Component#matches?` recurses into subcomponents, so
  `find_statements` / `effective_statement` resolve a lookup key that names
  any subcomponent inside the statement's product scope (not only the
  top-level product).
- `Vex::Document.generate_canonical_id(statements)` produces a
  deterministic `@id` (`{PUBLIC_NAMESPACE}/vex-<sha256>`) from the
  statements' immutable identifying fields. `Document#regenerate_id`
  applies it in-place. Mutable bookkeeping (`last_updated`, `status_notes`,
  statement-level timestamps) is excluded so equivalent updates don't
  churn the document ID.
- `Vex::Document.merge(docs, ...)` and `Document#merge(other)` union
  statements across documents, deduplicating value-equal ones. The merged
  document carries the full history; `effective_statement` picks the most
  recent ruling at lookup time. When `id:` is omitted, a canonical `@id`
  is generated from the merged statements.
- `Document#validate` now flags a nil document-level `timestamp`. The
  spec lists it as required at the document level; the prior per-statement
  inheritance check missed the case where every statement carried its own
  timestamp while the document had none.

### Changed (behavior tightening — may flip previously-`valid?` documents)
- `Statement#validate` now rejects:
  - `justification` and `impact_statement` set on `Fixed` or
    `UnderInvestigation` statuses (only meaningful under `not_affected`).
  - `action_statement_timestamp` set without an `action_statement` (the
    timestamp has nothing to qualify on its own).
  - Subcomponents that carry no `@id`, `identifiers`, or `hashes` (the
    same Component fields requirement already enforced on products).
- `Document#warnings` now also flags non-IRI `@id` on Document, Statement,
  Vulnerability, and Component, plus a non-IRI statement-level `supplier`.

## v0.1.0

- First release
