+++
title = "Vex::Status"
description = "OpenVEX status labels"
weight = 5
+++

`Vex::Status` is an enum carrying the four status labels the OpenVEX
spec defines.

## Members

| Member                | Wire string             |
|-----------------------|-------------------------|
| `NotAffected`         | `not_affected`          |
| `Affected`            | `affected`              |
| `Fixed`               | `fixed`                 |
| `UnderInvestigation`  | `under_investigation`   |

The wire string is what appears in JSON. `to_s` and `to_json` both
emit the wire string — there is no extra mapping to remember.

## Methods

### `wire_value : String`

Returns the spec-defined wire string for this status.

### `Vex::Status.parse_wire(value : String) : Vex::Status`

Parses a wire string into the enum. Raises `ArgumentError` for any
value not in the table above. JSON parsing uses this same routine.

### `to_s(io : IO) : Nil`

Writes the wire string to `io`. Calling `status.to_s` on
`Vex::Status::NotAffected` returns `"not_affected"`.

## Conditional fields by status

| Status                | Required                              | Forbidden                           |
|-----------------------|---------------------------------------|-------------------------------------|
| `not_affected`        | `justification` or `impact_statement` | `action_statement`                  |
| `affected`            | `action_statement`                    | `justification`, `impact_statement` |
| `fixed`               | none                                  | none                                |
| `under_investigation` | none                                  | none                                |

See [Validation](/user-guide/validation/) for the full rule set.
