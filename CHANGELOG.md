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
  deterministic `@id` (`{PUBLIC_NAMESPACE}/public/vex-<sha256>`) from the
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
- `Vex::Error` / `Vex::ParseError` exception hierarchy, matching the
  convention used across the sibling shards. `Vex::Document.from_json`,
  `Document.from_file`, and `Statement.from_json` translate JSON structure
  errors into `Vex::ParseError` (keeping the stdlib exception as `cause`),
  so every decode failure — malformed JSON, unknown `status` /
  `justification` label, unparsable timestamp — raises one type.
- `TimeConverter.parse` accepts the lower-case `t` / `z` spellings RFC 3339
  §5.6 permits (`2025-01-01t00:00:00z`).

### Fixed
- `Statement#validate` missed a stray `action_statement` on `fixed` and
  `under_investigation`. The spec scopes `action_statement` to `affected`
  ("For a statement with 'affected' status, a VEX statement MUST include a
  statement that SHOULD describe actions to remediate or mitigate"), and the
  same rule was already enforced for `not_affected`.
- `Document.generate_canonical_id` / `#regenerate_id` minted IRIs as
  `https://openvex.dev/docs/vex-<sha256>`, which places the document in an
  unregistered namespace named after its own hash. The spec's "Public IRI
  Namespaces" section defines `https://openvex.dev/docs/[name]` with `public`
  as the reserved shared name; IDs are now
  `https://openvex.dev/docs/public/vex-<sha256>`, matching go-vex.
- `TimeConverter.parse` accepted a well-formed timestamp followed by trailing
  junk (`"2025-01-01T00:00:00Zjunk"` parsed as a valid instant), because
  `Time::Format#parse` ignores whatever is left after the pattern. Values are
  now shape-checked end-to-end before parsing.
- Out-of-range timestamp components (`"2025-13-45T99:99:99Z"`) leaked a bare
  `ArgumentError: Invalid time` from `Time.local` through
  `Document.from_json`; they now raise `Vex::ParseError` naming the value.
- A document parsed without `@context`, `@id`, or `author` re-serialized
  those keys as `""` — spec-invalid values, and keys the input never had.
  They are now omitted, the same treatment `version: 0` already receives.
  `validate` still reports the missing fields.

### Changed (behavior tightening — may flip previously-`valid?` documents)
- `Statement#validate` now rejects:
  - `justification` and `impact_statement` set on `Fixed` or
    `UnderInvestigation` statuses (only meaningful under `not_affected`).
  - `action_statement_timestamp` set without an `action_statement` (the
    timestamp has nothing to qualify on its own).
  - Subcomponents that carry no `@id`, `identifiers`, or `hashes` (the
    same Component fields requirement already enforced on products).
  - `action_statement` set on `Fixed` or `UnderInvestigation` (only
    meaningful under `affected`).
- Unknown `status` / `justification` labels raise `Vex::ParseError` instead
  of `ArgumentError`, and unparsable timestamps raise `Vex::ParseError`
  instead of `Time::Format::Error`.
- `Document#warnings` now also flags non-IRI `@id` on Document, Statement,
  Vulnerability, and Component, plus a non-IRI statement-level `supplier`.

## v0.1.0

- First release
