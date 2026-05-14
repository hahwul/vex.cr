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
