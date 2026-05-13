+++
title = "Effective Statement"
description = "Resolve the most recent ruling for a (product, vulnerability) pair"
weight = 5
+++

A VEX document can contain multiple statements about the same
(product, vulnerability) pair over time — for example, an
`under_investigation` ruling later superseded by `not_affected`.
`Document#effective_statement` returns the **most recent** ruling.

## Basic usage

```crystal
doc = Vex::Document.from_file("vex.json")

eff = doc.effective_statement(
  "pkg:generic/example@1.0.0",
  "CVE-2024-0001",
)

if eff
  puts "status:    #{eff.status}"
  puts "issued at: #{eff.timestamp}"
  puts "reason:    #{eff.justification || eff.impact_statement || eff.action_statement || "n/a"}"
end
```

## Timestamp resolution

`effective_statement` compares statements by their `timestamp`, falling
back to the document `timestamp` for statements that don't set their
own. Ties resolve to the **last statement in source order** — matching
the reference `go-vex` implementation, which stable-sorts ascending and
iterates from the end. This honors the conceptual model that statements
appended later override older ones when their timestamps cannot.

## Alias-aware lookup

`Vex::Vulnerability#matches?` checks `@id`, `name`, and `aliases`, so
the lookup works through any known identifier:

```crystal
# Statement was authored with name=CVE-2024-0001, aliases=[GHSA-aaaa-bbbb-cccc]
doc.effective_statement("pkg:generic/example@1.0.0", "GHSA-aaaa-bbbb-cccc")
# => returns the same statement as looking it up by "CVE-2024-0001"
```

`Vex::Product#matches?` similarly checks both `@id` and every
`identifiers` value, so a lookup via `purl` matches a product authored
with an OCI digest in `@id` and the `purl` in `identifiers`.

## When no statement matches

`effective_statement` returns `nil` if no statement covers the
(product, vulnerability) pair. The caller decides the policy — treat
unknown as "not yet assessed", surface to a human, etc.

```crystal
case eff = doc.effective_statement(product, vuln)
when Nil
  puts "#{vuln}: no ruling on file"
else
  puts "#{vuln}: #{eff.status}"
end
```
