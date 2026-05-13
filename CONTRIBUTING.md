# Contributing

Thanks for your interest in vex.cr.

## Local development

```sh
shards install
crystal spec
crystal tool format --check
```

Run an example end-to-end:

```sh
crystal run examples/producer.cr
crystal run examples/consumer.cr
crystal run examples/round_trip.cr
```

## Submitting changes

1. Fork the repository and create a branch.
2. Add or update specs under `spec/` for any code change.
3. Make sure `crystal spec` and `crystal tool format --check` pass — CI runs both.
4. Open a pull request describing the change and linking to the relevant
   [OpenVEX v0.2.0 spec](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
   section if applicable.

## Reporting issues

Please open an issue with:

- A minimal VEX document (JSON) that triggers the problem.
- The expected behaviour, with a reference to the OpenVEX spec section.
- The actual behaviour vex.cr produced (error message, parsed value, or output JSON).

## Spec compliance

vex.cr targets the [OpenVEX v0.2.0 specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).
Bug reports citing a specific section of that document land fastest.
