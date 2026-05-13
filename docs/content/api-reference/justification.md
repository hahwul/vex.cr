+++
title = "Vex::Justification"
description = "OpenVEX justification labels for not_affected"
weight = 6
+++

`Vex::Justification` is an enum carrying the five justification labels
the OpenVEX spec defines for `not_affected` statements.

## Members

| Member                                       | Wire string                                          |
|----------------------------------------------|------------------------------------------------------|
| `ComponentNotPresent`                        | `component_not_present`                              |
| `VulnerableCodeNotPresent`                   | `vulnerable_code_not_present`                        |
| `VulnerableCodeNotInExecutePath`             | `vulnerable_code_not_in_execute_path`                |
| `VulnerableCodeCannotBeControlledByAdversary`| `vulnerable_code_cannot_be_controlled_by_adversary`  |
| `InlineMitigationsAlreadyExist`              | `inline_mitigations_already_exist`                   |

The wire string is what appears in JSON. `to_s` and `to_json` both emit
the wire string.

## Methods

### `wire_value : String`

Returns the spec-defined wire string.

### `Vex::Justification.parse_wire(value : String) : Vex::Justification`

Parses a wire string into the enum. Raises `ArgumentError` for any
value not in the table above. JSON parsing uses this same routine.

## When to use which

| Justification                                  | Reason                                                                 |
|------------------------------------------------|------------------------------------------------------------------------|
| `component_not_present`                        | The vulnerable component is not present in the product.                |
| `vulnerable_code_not_present`                  | The product includes the component but not the vulnerable code.        |
| `vulnerable_code_not_in_execute_path`          | The vulnerable code is shipped but never reachable at runtime.         |
| `vulnerable_code_cannot_be_controlled_by_adversary` | An attacker cannot reach the conditions to trigger the bug.       |
| `inline_mitigations_already_exist`             | The product ships compensating controls (sandbox, allow-list, ...).    |

See [§4.1 of the OpenVEX spec](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications)
for the authoritative definitions.

## Pairing with `impact_statement`

`not_affected` requires **either** a `justification` (from the enum
above) **or** an `impact_statement` (free-form prose). Set whichever
matches the situation — or both, if a justification needs added
context.

```crystal
Vex::Statement.new(
  status: Vex::Status::NotAffected,
  vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0001"),
  products: [Vex::Product.new(id: "pkg:generic/example@1.0.0")],
  justification: Vex::Justification::VulnerableCodeNotInExecutePath,
  impact_statement: "Build flag --no-tls excludes the vulnerable code path.",
)
```
