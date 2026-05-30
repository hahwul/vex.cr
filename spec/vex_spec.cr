require "./spec_helper"
require "json"

SPEC_EXAMPLE = <<-JSON
  {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
    "author": "Example Author",
    "role": "Document Creator",
    "timestamp": "2023-01-08T18:02:03.647787998-06:00",
    "version": 1,
    "statements": [
      {
        "vulnerability": {
          "name": "CVE-2023-12345"
        },
        "products": [
          {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"}
        ],
        "status": "fixed"
      }
    ]
  }
  JSON

STATUS_WIRE_PAIRS = [
  {Vex::Status::NotAffected, "not_affected"},
  {Vex::Status::Affected, "affected"},
  {Vex::Status::Fixed, "fixed"},
  {Vex::Status::UnderInvestigation, "under_investigation"},
]

JUSTIFICATION_WIRE_PAIRS = [
  {Vex::Justification::ComponentNotPresent, "component_not_present"},
  {Vex::Justification::VulnerableCodeNotPresent, "vulnerable_code_not_present"},
  {Vex::Justification::VulnerableCodeNotInExecutePath, "vulnerable_code_not_in_execute_path"},
  {Vex::Justification::VulnerableCodeCannotBeControlledByAdversary, "vulnerable_code_cannot_be_controlled_by_adversary"},
  {Vex::Justification::InlineMitigationsAlreadyExist, "inline_mitigations_already_exist"},
]

describe Vex::Status do
  STATUS_WIRE_PAIRS.each do |(member, wire)|
    it "round-trips #{wire}" do
      member.wire_value.should eq(wire)
      Vex::Status.parse_wire(wire).should eq(member)
      member.to_json.should eq(%("#{wire}"))
      Vex::Status.from_json(%("#{wire}")).should eq(member)
    end
  end

  it "writes wire value to IO via to_s" do
    io = IO::Memory.new
    Vex::Status::UnderInvestigation.to_s(io)
    io.to_s.should eq("under_investigation")
  end

  it "returns the wire value from the no-arg to_s (string interpolation)" do
    # Verifies the IO overload delegates correctly when the runtime invokes
    # `to_s` with no args (e.g. inside `puts`, `"#{status}"`, `String.build`).
    Vex::Status::NotAffected.to_s.should eq("not_affected")
    "#{Vex::Status::Fixed}".should eq("fixed")
  end

  it "raises on unknown wire value" do
    expect_raises(ArgumentError, /invalid VEX status/) do
      Vex::Status.parse_wire("bogus")
    end
  end

  it "raises when deserializing a JSON string with an unknown value" do
    expect_raises(ArgumentError, /invalid VEX status/) do
      Vex::Status.from_json(%("bogus"))
    end
  end
end

describe Vex::Justification do
  JUSTIFICATION_WIRE_PAIRS.each do |(member, wire)|
    it "round-trips #{wire}" do
      member.wire_value.should eq(wire)
      Vex::Justification.parse_wire(wire).should eq(member)
      member.to_json.should eq(%("#{wire}"))
      Vex::Justification.from_json(%("#{wire}")).should eq(member)
    end
  end

  it "returns the wire value from the no-arg to_s (string interpolation)" do
    Vex::Justification::ComponentNotPresent.to_s.should eq("component_not_present")
    "#{Vex::Justification::InlineMitigationsAlreadyExist}".should eq("inline_mitigations_already_exist")
  end

  it "raises on unknown wire value" do
    expect_raises(ArgumentError, /invalid VEX justification/) do
      Vex::Justification.parse_wire("hand-wave")
    end
  end

  it "raises when deserializing a JSON string with an unknown value" do
    expect_raises(ArgumentError, /invalid VEX justification/) do
      Vex::Justification.from_json(%("hand-wave"))
    end
  end
end

describe Vex::TimeConverter do
  it "parses RFC 3339 with nanosecond precision and offset" do
    t = Vex::TimeConverter.parse("2023-01-08T18:02:03.647787998-06:00")
    t.year.should eq(2023)
    t.month.should eq(1)
    t.day.should eq(8)
    t.offset.should eq(-6 * 3600)
  end

  it "parses simple UTC timestamps with Z suffix" do
    t = Vex::TimeConverter.parse("2024-05-10T12:34:56Z")
    t.year.should eq(2024)
    t.offset.should eq(0)
  end

  it "parses second-precision timestamps with numeric offset" do
    t = Vex::TimeConverter.parse("2024-05-10T12:34:56+09:00")
    t.hour.should eq(12)
    t.offset.should eq(9 * 3600)
  end

  it "parses fractional-second UTC timestamps" do
    t = Vex::TimeConverter.parse("2024-05-10T12:34:56.123Z")
    t.year.should eq(2024)
  end

  it "raises on a non-RFC-3339 string" do
    expect_raises(Time::Format::Error, /Could not parse/) do
      Vex::TimeConverter.parse("not a timestamp")
    end
  end

  it "leniently parses an RFC-3339-ish timestamp with no timezone as UTC" do
    # Some real-world VEX producers (e.g. Canonical's Ubuntu Security Notice
    # documents) emit timestamps without a zone. The spec mandates RFC 3339
    # with a zone, but for interoperability we treat the missing zone as UTC
    # rather than rejecting the document outright.
    t = Vex::TimeConverter.parse("2024-05-10T12:34:56")
    t.offset.should eq(0)
    t.year.should eq(2024)
  end

  it "leniently parses space-separated timestamps as UTC" do
    # Canonical's USN VEX docs use `"2025-07-08 22:59:24.546301"`.
    t = Vex::TimeConverter.parse("2025-07-08 22:59:24.546301")
    t.offset.should eq(0)
    t.year.should eq(2025)
    t.month.should eq(7)
  end

  it "emits UTC timestamps with the Z suffix (matching go-vex byte-for-byte)" do
    # UTC times should render as `...Z`, not `...+00:00`. Both are valid
    # RFC 3339, but the spec's reference example and go-vex's renderer use
    # `Z`. This is what makes our JSON byte-equivalent to go-vex's output.
    rendered = Vex::TimeConverter.format(Time.utc(2024, 5, 1, 12, 0, 0))
    rendered.should end_with("Z")
    rendered.should_not contain("+00:00")
  end

  it "emits non-UTC timestamps with an explicit numeric offset" do
    offset = Time::Location.fixed(-6 * 3600)
    t = Time.local(2024, 5, 1, 12, 0, 0, location: offset)
    rendered = Vex::TimeConverter.format(t)
    rendered.should end_with("-06:00")
  end

  it "format produces a value that parses back to the same instant" do
    original = Time.utc(2024, 5, 10, 12, 34, 56, nanosecond: 987_654_321)
    rendered = Vex::TimeConverter.format(original)
    Vex::TimeConverter.parse(rendered).should eq(original)
  end

  it "round-trips via JSON converter through Document timestamps" do
    instant = Time.utc(2025, 1, 2, 3, 4, 5, nanosecond: 6_000_000)
    doc = Vex::Document.new(
      id: "https://example.com/vex/ts",
      author: "tester",
      timestamp: instant,
    )
    reparsed = Vex::Document.from_json(doc.to_json)
    reparsed.timestamp.should eq(instant)
  end
end

describe Vex::Document do
  it "parses the spec's minimal example" do
    doc = Vex::Document.from_json(SPEC_EXAMPLE)
    doc.context.should eq("https://openvex.dev/ns/v0.2.0")
    doc.id.should eq("https://openvex.dev/docs/example/vex-9fb3463de1b57")
    doc.author.should eq("Example Author")
    doc.role.should eq("Document Creator")
    doc.version.should eq(1)
    doc.statements.size.should eq(1)

    stmt = doc.statements.first
    stmt.status.should eq(Vex::Status::Fixed)
    stmt.vulnerability.try(&.name).should eq("CVE-2023-12345")
    stmt.products.try(&.first.id).should eq("pkg:apk/wolfi/git@2.39.0-r1?arch=armv7")
  end

  it "round-trips the spec example without dropping or renaming fields" do
    doc = Vex::Document.from_json(SPEC_EXAMPLE)
    rendered = JSON.parse(doc.to_json)
    original = JSON.parse(SPEC_EXAMPLE)

    # Timestamps may re-format (e.g. nanosecond precision), so compare them
    # semantically and strip them from the structural comparison below.
    Vex::TimeConverter.parse(rendered["timestamp"].as_s)
      .should eq(Vex::TimeConverter.parse(original["timestamp"].as_s))

    rendered_h = rendered.as_h.dup
    original_h = original.as_h.dup
    rendered_h.delete("timestamp")
    original_h.delete("timestamp")
    rendered_h.should eq(original_h)
  end

  it "constructs a not_affected statement with justification" do
    doc = Vex::Document.new(
      id: "https://example.com/vex/ex1",
      author: "tester",
    )
    doc.add_statement(
      Vex::Statement.new(
        status: Vex::Status::NotAffected,
        vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0001"),
        products: [Vex::Product.new(id: "pkg:generic/example@1.0.0")],
        justification: Vex::Justification::VulnerableCodeNotInExecutePath,
      ),
    )

    doc.valid?.should be_true

    rendered = doc.to_json
    parsed = JSON.parse(rendered)
    parsed["statements"][0]["status"].should eq("not_affected")
    parsed["statements"][0]["justification"].should eq("vulnerable_code_not_in_execute_path")
    # No action_statement / impact_statement keys should be emitted.
    parsed["statements"][0].as_h.has_key?("action_statement").should be_false
    parsed["statements"][0].as_h.has_key?("impact_statement").should be_false
  end

  it "constructs an affected statement with action_statement" do
    stmt = Vex::Statement.new(
      status: Vex::Status::Affected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0002"),
      products: [Vex::Product.new(id: "pkg:generic/app@1.0.0")],
      action_statement: "Upgrade to 1.1.0",
    )
    stmt.valid?.should be_true
    JSON.parse(stmt.to_json)["action_statement"].should eq("Upgrade to 1.1.0")
  end

  it "accepts not_affected with only impact_statement (no justification)" do
    stmt = Vex::Statement.new(
      status: Vex::Status::NotAffected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0006"),
      products: [Vex::Product.new(id: "pkg:generic/app@1.0.0")],
      impact_statement: "The vulnerable feature is disabled by default.",
    )
    stmt.valid?.should be_true
    parsed = JSON.parse(stmt.to_json)
    parsed["impact_statement"].should eq("The vulnerable feature is disabled by default.")
    parsed.as_h.has_key?("justification").should be_false
  end

  it "flags not_affected without justification or impact_statement" do
    stmt = Vex::Statement.new(
      status: Vex::Status::NotAffected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-2024-9999"),
    )
    stmt.valid?.should be_false
    stmt.validate.first.should contain("justification or impact_statement")
  end

  it "flags affected without action_statement" do
    stmt = Vex::Statement.new(
      status: Vex::Status::Affected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0003"),
    )
    stmt.valid?.should be_false
  end

  it "flags affected with stray justification" do
    stmt = Vex::Statement.new(
      status: Vex::Status::Affected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0004"),
      action_statement: "Upgrade",
      justification: Vex::Justification::ComponentNotPresent,
    )
    stmt.valid?.should be_false
  end

  it "supports products with subcomponents, identifiers, and hashes" do
    product = Vex::Product.new(
      id: "pkg:generic/parent@1.0.0",
      identifiers: {"purl" => "pkg:generic/parent@1.0.0"},
      hashes: {"sha-256" => "abc123"},
      subcomponents: [
        Vex::Subcomponent.new(id: "pkg:generic/child@0.1.0"),
      ],
    )
    json = product.to_json
    parsed = JSON.parse(json)
    parsed["@id"].should eq("pkg:generic/parent@1.0.0")
    parsed["identifiers"]["purl"].should eq("pkg:generic/parent@1.0.0")
    parsed["hashes"]["sha-256"].should eq("abc123")
    parsed["subcomponents"][0]["@id"].should eq("pkg:generic/child@0.1.0")
  end

  it "resolves effective_statement ties to the last statement in source order" do
    # Matches go-vex behavior (stable sort ascending then iterate from end):
    # when two statements share a timestamp, the one declared later wins,
    # honoring the "newer statements override" model when ts cannot.
    same_ts = Time.utc(2024, 1, 1)
    older = Vex::Statement.new(
      status: Vex::Status::UnderInvestigation,
      vulnerability: Vex::Vulnerability.new(name: "CVE-T"),
      products: [Vex::Product.new(id: "pkg:t")],
      timestamp: same_ts,
    )
    newer = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-T"),
      products: [Vex::Product.new(id: "pkg:t")],
      timestamp: same_ts,
    )
    doc = Vex::Document.new(
      id: "https://example.com/vex/tie",
      author: "t",
      statements: [older, newer],
    )
    doc.effective_statement("pkg:t", "CVE-T").try(&.status).should eq(Vex::Status::Fixed)
  end

  it "computes effective_statement by latest timestamp" do
    older = Vex::Statement.new(
      status: Vex::Status::UnderInvestigation,
      vulnerability: Vex::Vulnerability.new(name: "CVE-2024-1111"),
      products: [Vex::Product.new(id: "pkg:generic/app@1.0.0")],
      timestamp: Time.utc(2024, 1, 1),
    )
    newer = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-2024-1111"),
      products: [Vex::Product.new(id: "pkg:generic/app@1.0.0")],
      timestamp: Time.utc(2024, 6, 1),
    )
    doc = Vex::Document.new(
      id: "https://example.com/vex/ex2",
      author: "tester",
      statements: [older, newer],
    )
    eff = doc.effective_statement("pkg:generic/app@1.0.0", "CVE-2024-1111")
    eff.should_not be_nil
    eff.not_nil!.status.should eq(Vex::Status::Fixed)
  end

  it "round-trips aliases on vulnerabilities" do
    vuln = Vex::Vulnerability.new(
      name: "CVE-2024-0005",
      aliases: ["GHSA-xxxx-yyyy-zzzz"],
      description: "example",
      id: "https://nvd.nist.gov/vuln/detail/CVE-2024-0005",
    )
    parsed = Vex::Vulnerability.from_json(vuln.to_json)
    parsed.name.should eq("CVE-2024-0005")
    parsed.aliases.should eq(["GHSA-xxxx-yyyy-zzzz"])
    parsed.id.should eq("https://nvd.nist.gov/vuln/detail/CVE-2024-0005")
  end

  it "uses sensible defaults from version constants" do
    doc = Vex::Document.new(id: "https://example.com/vex/defaults")
    doc.context.should eq(Vex::CONTEXT)
    doc.context.should eq("https://openvex.dev/ns/v0.2.0")
    doc.author.should eq(Vex::DEFAULT_AUTHOR)
    doc.version.should eq(1)
    doc.statements.should be_empty
    doc.timestamp.should_not be_nil
  end

  it "round-trips all optional document fields" do
    doc = Vex::Document.new(
      id: "https://example.com/vex/full",
      author: "tester",
      role: "Document Creator",
      tooling: "vex.cr/#{Vex::VERSION}",
      timestamp: Time.utc(2025, 3, 1),
      last_updated: Time.utc(2025, 3, 2),
      version: 7,
    )
    reparsed = Vex::Document.from_json(doc.to_json)
    reparsed.role.should eq("Document Creator")
    reparsed.tooling.should eq("vex.cr/#{Vex::VERSION}")
    reparsed.last_updated.should eq(Time.utc(2025, 3, 2))
    reparsed.version.should eq(7)
  end

  it "omits optional document fields when unset" do
    doc = Vex::Document.new(id: "https://example.com/vex/min", author: "x")
    parsed = JSON.parse(doc.to_json).as_h
    parsed.has_key?("role").should be_false
    parsed.has_key?("tooling").should be_false
    parsed.has_key?("last_updated").should be_false
  end

  it "never re-emits an invalid version:0 when round-tripping a version-less document" do
    # A producer may hand us a document that omits `version` (we parse it
    # permissively, defaulting the sentinel to 0). Re-serializing must NOT
    # emit `"version": 0`, which the spec (and our own validate) rejects.
    json = %({"@context":"x","@id":"y","author":"a","statements":[]})
    doc = Vex::Document.from_json(json)
    doc.version.should eq(0)
    parsed = JSON.parse(doc.to_json).as_h
    parsed.has_key?("version").should be_false
    doc.validate.any?(&.includes?("version")).should be_true
  end

  it "serializes a valid version normally" do
    doc = Vex::Document.new(id: "https://example.com/vex/v", author: "x", version: 3)
    JSON.parse(doc.to_json).as_h["version"].should eq(3)
  end

  it "does not declare supplier at the document level (removed in spec 2023-06-01)" do
    # The OpenVEX revision history lists "Removed supplier from the document
    # level (following VEX-WG doc)." Make sure round-tripping a document JSON
    # that still carries `supplier` (some legacy producers do) silently drops
    # it instead of being treated as required output.
    json = %({"@context":"x","@id":"y","author":"a","version":1,"statements":[],"supplier":"https://legacy.example"})
    Vex::Document.from_json(json).to_json.includes?("supplier").should be_false
  end

  it "round-trips all optional statement fields" do
    stmt = Vex::Statement.new(
      id: "https://example.com/vex/full#stmt-1",
      version: 3,
      status: Vex::Status::Affected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-2024-7777"),
      products: [Vex::Product.new(id: "pkg:generic/app@1.0.0")],
      timestamp: Time.utc(2025, 4, 1),
      last_updated: Time.utc(2025, 4, 2),
      status_notes: "from internal triage",
      action_statement: "Upgrade to 1.0.1",
      action_statement_timestamp: Time.utc(2025, 4, 3),
      supplier: "https://example.com",
    )
    reparsed = Vex::Statement.from_json(stmt.to_json)
    reparsed.id.should eq("https://example.com/vex/full#stmt-1")
    reparsed.version.should eq(3)
    reparsed.last_updated.should eq(Time.utc(2025, 4, 2))
    reparsed.status_notes.should eq("from internal triage")
    reparsed.action_statement_timestamp.should eq(Time.utc(2025, 4, 3))
    reparsed.supplier.should eq("https://example.com")
  end

  it "strips a UTF-8 BOM when reading via from_file" do
    # Windows-emitted JSON commonly carries a UTF-8 BOM. Crystal's JSON
    # parser rejects it; from_file should tolerate it.
    path = File.tempname("vex-bom-", ".json")
    begin
      File.write(path, "\u{FEFF}" + %({"@context": "x", "@id": "y", "author": "a", "version": 1, "statements": []}))
      doc = Vex::Document.from_file(path)
      doc.id.should eq("y")
    ensure
      File.delete(path) if File.exists?(path)
    end
  end

  it "writes to and reads back from a file" do
    doc = Vex::Document.new(
      id: "https://example.com/vex/io",
      author: "tester",
    )
    doc.add_statement(
      Vex::Statement.new(
        status: Vex::Status::Fixed,
        vulnerability: Vex::Vulnerability.new(name: "CVE-2024-8888"),
        products: [Vex::Product.new(id: "pkg:generic/app@1.0.1")],
      ),
    )

    path = File.tempname("vex", ".json")
    begin
      doc.write(path)
      File.exists?(path).should be_true
      loaded = Vex::Document.from_file(path)
      loaded.statements.size.should eq(1)
      loaded.statements.first.status.should eq(Vex::Status::Fixed)
    ensure
      File.delete(path) if File.exists?(path)
    end
  end

  it "emits indented JSON via to_json_pretty" do
    doc = Vex::Document.new(id: "https://example.com/vex/pp", author: "x")
    doc.to_json_pretty.includes?("\n  ").should be_true
  end

  it "ignores unknown JSON fields for forward compatibility" do
    json = <<-JSON
      {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/vex/fwd",
        "author": "x",
        "version": 1,
        "timestamp": "2025-01-01T00:00:00Z",
        "statements": [],
        "some_future_field": {"x": 1}
      }
      JSON
    doc = Vex::Document.from_json(json)
    doc.id.should eq("https://example.com/vex/fwd")
  end

  it "raises when status is missing from JSON" do
    expect_raises(JSON::ParseException) do
      Vex::Statement.from_json(%({"vulnerability": {"name": "CVE-1"}}))
    end
  end

  # Real-world fixtures (go-vex testdata/v020-*.vex.json) omit the document
  # `version` field even though the OpenVEX v0.2.0 spec lists it as required.
  # Parsing must succeed; `validate` is the place that surfaces the gap.
  it "parses documents that omit document-level metadata (go-vex-style permissive)" do
    json = <<-JSON
      {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/vex/no-version",
        "author": "John Doe",
        "statements": [
          {
            "timestamp": "2022-12-22T16:36:43-05:00",
            "products": [{"@id": "pkg:apk/wolfi/bash@1.0.0"}],
            "vulnerability": {"name": "CVE-9876-54321"},
            "status": "under_investigation"
          }
        ]
      }
      JSON
    doc = Vex::Document.from_json(json)
    doc.version.should eq(0)
    doc.statements.size.should eq(1)
    doc.validate.any?(&.includes?("version")).should be_true
  end

  it "tolerates missing @context, @id, author with empty-string defaults" do
    doc = Vex::Document.from_json(%({"statements": []}))
    doc.context.should eq("")
    doc.id.should eq("")
    doc.author.should eq("")
    errors = doc.validate
    errors.any?(&.includes?("@context")).should be_true
    errors.any?(&.includes?("@id")).should be_true
    errors.any?(&.includes?("author")).should be_true
  end

  it "tolerates null and missing statements arrays with empty default" do
    Vex::Document.from_json(%({"@context": "x", "@id": "y", "author": "a", "version": 1}))
      .statements.should be_empty
    Vex::Document.from_json(%({"@context": "x", "@id": "y", "author": "a", "version": 1, "statements": null}))
      .statements.should be_empty
  end
end

describe "value equality" do
  it "Vulnerability equality compares fields, not identity" do
    a = Vex::Vulnerability.new(name: "CVE-X", aliases: ["GHSA-1"])
    b = Vex::Vulnerability.new(name: "CVE-X", aliases: ["GHSA-1"])
    c = Vex::Vulnerability.new(name: "CVE-X", aliases: ["GHSA-2"])
    a.should eq(b)
    a.should_not eq(c)
    a.hash.should eq(b.hash)
  end

  it "Component and Product equality" do
    a = Vex::Product.new(id: "pkg:a", subcomponents: [Vex::Subcomponent.new(id: "sub:1")])
    b = Vex::Product.new(id: "pkg:a", subcomponents: [Vex::Subcomponent.new(id: "sub:1")])
    a.should eq(b)
  end

  it "Statement equality" do
    s1 = Vex::Statement.new(status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x")])
    s2 = Vex::Statement.new(status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x")])
    s1.should eq(s2)
  end

  it "Document equality and round-trip yields equal docs" do
    doc = Vex::Document.new(
      id: "https://x/eq", author: "t", timestamp: Time.utc(2024, 1, 1),
      statements: [Vex::Statement.new(status: Vex::Status::Fixed,
        vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
        products: [Vex::Product.new(id: "pkg:x")])],
    )
    reparsed = Vex::Document.from_json(doc.to_json)
    reparsed.should eq(doc)
  end

  it "supports Set membership" do
    set = Set(Vex::Vulnerability).new
    set << Vex::Vulnerability.new(name: "CVE-X")
    set << Vex::Vulnerability.new(name: "CVE-X")
    set << Vex::Vulnerability.new(name: "CVE-Y")
    set.size.should eq(2)
  end
end

describe "Vex::Vulnerability#validate" do
  it "is valid with a name" do
    Vex::Vulnerability.new(name: "CVE-2024-1").valid?.should be_true
  end

  it "flags a missing name" do
    v = Vex::Vulnerability.new(id: "https://nvd.nist.gov/vuln/detail/CVE-2024-2")
    v.valid?.should be_false
    v.validate.first.should contain("name")
  end

  it "flags an empty name" do
    Vex::Vulnerability.new(name: "").valid?.should be_false
  end
end

describe "Statement#validate vulnerability requirement" do
  it "flags a statement with no vulnerability" do
    stmt = Vex::Statement.new(status: Vex::Status::Fixed)
    stmt.valid?.should be_false
    stmt.validate.any?(&.includes?("vulnerability is required")).should be_true
  end

  it "propagates vulnerability validation errors" do
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(id: "urn:x"),
    )
    stmt.validate.any?(&.matches?(/vulnerability: name/)).should be_true
  end
end

describe Vex::Vulnerability do
  it "matches by name" do
    v = Vex::Vulnerability.new(name: "CVE-2024-1")
    v.matches?("CVE-2024-1").should be_true
  end

  it "matches by IRI id" do
    v = Vex::Vulnerability.new(
      name: "CVE-2024-2",
      id: "https://nvd.nist.gov/vuln/detail/CVE-2024-2",
    )
    v.matches?("https://nvd.nist.gov/vuln/detail/CVE-2024-2").should be_true
  end

  it "matches by alias" do
    v = Vex::Vulnerability.new(
      name: "CVE-2024-3",
      aliases: ["GHSA-aaaa-bbbb-cccc", "OSV-2024-9"],
    )
    v.matches?("GHSA-aaaa-bbbb-cccc").should be_true
    v.matches?("OSV-2024-9").should be_true
  end

  it "returns false when no identifier matches" do
    v = Vex::Vulnerability.new(name: "CVE-2024-4")
    v.matches?("CVE-9999-9").should be_false
  end
end

describe Vex::Component do
  it "matches by @id" do
    c = Vex::Component.new(id: "pkg:generic/app@1.0.0")
    c.matches?("pkg:generic/app@1.0.0").should be_true
  end

  it "matches by identifier value" do
    c = Vex::Component.new(
      identifiers: {"purl" => "pkg:generic/app@1.0.0", "cpe23" => "cpe:2.3:a:vendor:app:1.0.0:*:*:*:*:*:*:*"},
    )
    c.matches?("pkg:generic/app@1.0.0").should be_true
    c.matches?("cpe:2.3:a:vendor:app:1.0.0:*:*:*:*:*:*:*").should be_true
  end

  it "returns false when nothing matches" do
    c = Vex::Component.new(id: "pkg:generic/app@1.0.0")
    c.matches?("pkg:generic/other@1.0.0").should be_false
  end

  it "does not match when both @id and identifiers are absent" do
    c = Vex::Component.new(hashes: {"sha-256" => "abc"})
    c.matches?("").should be_false
    c.matches?("anything").should be_false
  end

  it "does not declare supplier on a component (per spec Component fields table)" do
    # Spec lists supplier at the Statement level only. Round-tripping a legacy
    # component carrying `supplier` should drop the field rather than carry
    # it forward.
    parsed = Vex::Component.from_json(%({"@id":"pkg:x","supplier":"https://legacy"}))
    parsed.to_json.includes?("supplier").should be_false
  end
end

describe Vex::Subcomponent do
  it "round-trips standalone (verifies JSON::Serializable inheritance)" do
    sub = Vex::Subcomponent.new(
      id: "pkg:generic/child@0.1.0",
      identifiers: {"purl" => "pkg:generic/child@0.1.0"},
      hashes: {"sha-256" => "deadbeef"},
    )
    parsed = Vex::Subcomponent.from_json(sub.to_json)
    parsed.id.should eq("pkg:generic/child@0.1.0")
    parsed.identifiers.try(&.["purl"]).should eq("pkg:generic/child@0.1.0")
    parsed.hashes.try(&.["sha-256"]).should eq("deadbeef")
  end

  it "supports nested subcomponents (spec lists subcomponents on Component)" do
    # The Component fields table puts `subcomponents` on Component itself, so
    # a Subcomponent may itself nest further components — e.g. a container
    # image embedding a library that embeds a vendored dep.
    leaf = Vex::Subcomponent.new(id: "pkg:generic/leaf@0.0.1")
    mid = Vex::Subcomponent.new(id: "pkg:generic/mid@0.0.1", subcomponents: [leaf])
    parsed = Vex::Subcomponent.from_json(mid.to_json)
    parsed.subcomponents.try(&.first.id).should eq("pkg:generic/leaf@0.0.1")
  end

  it "matches by a nested subcomponent's identifier" do
    leaf = Vex::Subcomponent.new(id: "pkg:generic/leaf@0.0.1")
    mid = Vex::Subcomponent.new(id: "pkg:generic/mid@0.0.1", subcomponents: [leaf])
    parent = Vex::Product.new(id: "pkg:generic/parent@1.0.0", subcomponents: [mid])
    parent.matches?("pkg:generic/leaf@0.0.1").should be_true
    parent.matches?("pkg:generic/mid@0.0.1").should be_true
  end
end

describe "Statement#validate edge cases" do
  it "treats Fixed status as valid without status-specific fields" do
    Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
    ).valid?.should be_true
  end

  it "treats UnderInvestigation status as valid without status-specific fields" do
    Vex::Statement.new(
      status: Vex::Status::UnderInvestigation,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
    ).valid?.should be_true
  end

  it "flags fixed with stray justification" do
    # Spec: justification only carries meaning under not_affected — explains
    # *why* a product is not affected. On `fixed` it's a producer mistake.
    errors = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      justification: Vex::Justification::ComponentNotPresent,
    ).validate
    errors.any?(&.includes?("justification must not be set")).should be_true
  end

  it "flags fixed with stray impact_statement" do
    errors = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      impact_statement: "not reachable",
    ).validate
    errors.any?(&.includes?("impact_statement must not be set")).should be_true
  end

  it "flags under_investigation with stray justification" do
    errors = Vex::Statement.new(
      status: Vex::Status::UnderInvestigation,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      justification: Vex::Justification::ComponentNotPresent,
    ).validate
    errors.any?(&.includes?("justification must not be set")).should be_true
  end

  it "flags under_investigation with stray impact_statement" do
    errors = Vex::Statement.new(
      status: Vex::Status::UnderInvestigation,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      impact_statement: "tbd",
    ).validate
    errors.any?(&.includes?("impact_statement must not be set")).should be_true
  end

  it "flags action_statement_timestamp without an action_statement" do
    # The timestamp is meant to qualify the action_statement; orphaning it
    # leaves nothing for the timestamp to describe.
    errors = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      action_statement_timestamp: Time.utc(2024, 1, 1),
    ).validate
    errors.any?(&.includes?("action_statement_timestamp")).should be_true
  end

  it "accepts action_statement_timestamp paired with action_statement" do
    Vex::Statement.new(
      status: Vex::Status::Affected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x")],
      action_statement: "Upgrade to 1.1.0",
      action_statement_timestamp: Time.utc(2024, 1, 1),
    ).valid?.should be_true
  end

  it "flags not_affected with stray action_statement" do
    errors = Vex::Statement.new(
      status: Vex::Status::NotAffected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      justification: Vex::Justification::ComponentNotPresent,
      action_statement: "stray",
    ).validate
    errors.any?(&.includes?("action_statement")).should be_true
  end

  it "flags affected with stray impact_statement" do
    errors = Vex::Statement.new(
      status: Vex::Status::Affected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      action_statement: "Upgrade",
      impact_statement: "stray",
    ).validate
    errors.any?(&.includes?("impact_statement")).should be_true
  end

  it "accumulates multiple violations" do
    errors = Vex::Statement.new(
      status: Vex::Status::Affected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      justification: Vex::Justification::ComponentNotPresent,
      impact_statement: "stray",
    ).validate
    # missing action_statement + stray justification + stray impact_statement
    errors.size.should eq(3)
  end

  it "treats not_affected with an empty impact_statement as missing" do
    # An empty string is structurally "set" but semantically blank; the spec
    # requires conveyance of *why*, so empty impact_statement does not
    # satisfy the not_affected requirement.
    errors = Vex::Statement.new(
      status: Vex::Status::NotAffected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      impact_statement: "",
    ).validate
    errors.any?(&.includes?("justification or impact_statement")).should be_true
  end

  it "treats affected with an empty action_statement as missing" do
    errors = Vex::Statement.new(
      status: Vex::Status::Affected,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      action_statement: "",
    ).validate
    errors.any?(&.includes?("action_statement")).should be_true
  end
end

describe "nested subcomponent validation and lookup" do
  it "flags an unidentifiable component at depth 2 with the full path" do
    deep = Vex::Subcomponent.new # no @id / identifiers / hashes
    mid = Vex::Subcomponent.new(id: "pkg:mid", subcomponents: [deep])
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-NESTED"),
      products: [Vex::Product.new(id: "pkg:parent", subcomponents: [mid])],
    )
    errs = stmt.validate
    errs.any? { |e| e.includes?("products[0].subcomponents[0].subcomponents[0]") && e.includes?("no @id") }.should be_true
  end

  it "surfaces a depth-2 component warning via Document#warnings" do
    deep = Vex::Subcomponent.new(id: "pkg:deep", hashes: {"sha-128" => "ab"})
    mid = Vex::Subcomponent.new(id: "pkg:mid", subcomponents: [deep])
    doc = Vex::Document.new(id: "https://example.com/vex/nested", author: "x")
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:parent", subcomponents: [mid])],
    ))
    doc.warnings.any? do |w|
      w.includes?("products[0].subcomponents[0].subcomponents[0]") && w.includes?("Appendix A")
    end.should be_true
  end

  it "find_statements matches when the lookup key names a subcomponent" do
    # A producer issues a VEX about parent P that names subcomponent S in its
    # scope. A consumer asking "is S affected" should hit the statement.
    doc = Vex::Document.new(
      id: "https://example.com/vex/sub-match",
      author: "t",
      statements: [
        Vex::Statement.new(
          status: Vex::Status::NotAffected,
          vulnerability: Vex::Vulnerability.new(name: "CVE-SUB"),
          products: [Vex::Product.new(
            id: "pkg:parent",
            subcomponents: [Vex::Subcomponent.new(id: "pkg:child@0.1.0")],
          )],
          justification: Vex::Justification::ComponentNotPresent,
        ),
      ],
    )
    doc.find_statements("pkg:child@0.1.0", "CVE-SUB").size.should eq(1)
    doc.effective_statement("pkg:child@0.1.0", "CVE-SUB").try(&.status).should eq(Vex::Status::NotAffected)
  end
end

describe "Statement#validate product identifiability" do
  it "flags a product with no @id, identifiers, or hashes" do
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new],
    )
    stmt.validate.any?(&.includes?("no @id")).should be_true
  end

  it "accepts a product identified by hashes only" do
    Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(hashes: {"sha-256" => "ab"})],
    ).valid?.should be_true
  end

  it "accepts a product identified by identifiers only" do
    Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(identifiers: {"purl" => "pkg:x"})],
    ).valid?.should be_true
  end

  it "treats empty identifiers/hashes maps on a product as unidentifiable" do
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(
        identifiers: {} of String => String,
        hashes: {} of String => String,
      )],
    )
    stmt.validate.any?(&.includes?("no @id")).should be_true
  end

  it "flags a subcomponent with no @id, identifiers, or hashes" do
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(
        id: "pkg:parent",
        subcomponents: [Vex::Subcomponent.new],
      )],
    )
    stmt.validate.any? { |e| e.includes?("subcomponents[0]") && e.includes?("no @id") }.should be_true
  end

  it "accepts an identifiable subcomponent" do
    Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(
        id: "pkg:parent",
        subcomponents: [Vex::Subcomponent.new(id: "pkg:child@0.1.0")],
      )],
    ).valid?.should be_true
  end
end

describe "Vex::Component#identified?" do
  it "is true with @id" do
    Vex::Component.new(id: "pkg:x").identified?.should be_true
  end

  it "is true with non-empty identifiers" do
    Vex::Component.new(identifiers: {"purl" => "pkg:x"}).identified?.should be_true
  end

  it "is true with non-empty hashes" do
    Vex::Component.new(hashes: {"sha-256" => "ab"}).identified?.should be_true
  end

  it "is false when all identifying fields are absent" do
    Vex::Component.new.identified?.should be_false
  end

  it "is false when identifiers and hashes are present but empty" do
    Vex::Component.new(
      identifiers: {} of String => String,
      hashes: {} of String => String,
    ).identified?.should be_false
  end
end

describe "Document#validate spec invariants" do
  it "flags duplicate statement @id" do
    doc = Vex::Document.new(id: "https://x/d", author: "t")
    doc.add_statement(Vex::Statement.new(
      id: "https://x/d#s1",
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-A"),
      products: [Vex::Product.new(id: "pkg:a")],
    ))
    doc.add_statement(Vex::Statement.new(
      id: "https://x/d#s1", # duplicate
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-B"),
      products: [Vex::Product.new(id: "pkg:b")],
    ))
    doc.validate.any?(&.includes?("duplicate @id")).should be_true
  end

  it "allows multiple statements with no @id (the nil case is unique-vacuously)" do
    doc = Vex::Document.new(id: "https://x/d", author: "t")
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-A"),
      products: [Vex::Product.new(id: "pkg:a")],
    ))
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-B"),
      products: [Vex::Product.new(id: "pkg:b")],
    ))
    doc.valid?.should be_true
  end
end

describe "Document#validate edge cases" do
  it "flags an empty @id" do
    doc = Vex::Document.new(id: "", author: "x")
    doc.validate.any?(&.includes?("@id")).should be_true
  end

  it "flags an empty author" do
    doc = Vex::Document.new(id: "https://example.com/vex/x", author: "")
    doc.validate.any?(&.includes?("author")).should be_true
  end

  it "flags version < 1" do
    doc = Vex::Document.new(id: "https://example.com/vex/x", author: "x", version: 0)
    doc.validate.any?(&.includes?("version")).should be_true
  end

  it "flags a nil document-level timestamp even when statements supply their own" do
    # Spec lists doc-level `timestamp` as required. If a parse drops it but
    # every statement has its own, the per-statement timestamp check passes
    # — so the doc-level rule needs its own enforcement.
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x")],
      timestamp: Time.utc(2024, 1, 1),
    )
    doc = Vex::Document.new(
      id: "https://example.com/vex/no-doc-ts",
      author: "x",
      timestamp: nil,
      statements: [stmt],
    )
    doc.validate.any?(&.includes?("timestamp must be set at the document level")).should be_true
  end

  it "surfaces statement violations with their index" do
    doc = Vex::Document.new(id: "https://example.com/vex/x", author: "x")
    doc.add_statement(
      Vex::Statement.new(
        status: Vex::Status::NotAffected,
        vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      ),
    )
    doc.validate.first.should match(/statements\[0\]:/)
  end
end

describe "Component#warnings (Appendix A / B labels)" do
  it "is silent when hash and identifier keys are in the spec tables" do
    c = Vex::Component.new(
      hashes: {"sha-256" => "abc", "blake2b-512" => "def"},
      identifiers: {"purl" => "pkg:x", "cpe23" => "cpe:2.3:..."},
    )
    c.warnings.should be_empty
  end

  it "flags hash algorithms not in Appendix A" do
    c = Vex::Component.new(hashes: {"sha-128" => "abc"})
    c.warnings.first.should contain("Appendix A")
  end

  it "flags identifier types not in Appendix B" do
    c = Vex::Component.new(identifiers: {"oci" => "..."})
    c.warnings.first.should contain("Appendix B")
  end
end

describe "Document#warnings" do
  it "is silent for a spec-conformant document" do
    doc = Vex::Document.new(id: "https://example.com/vex/w", author: "x")
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x", hashes: {"sha-256" => "ab"})],
    ))
    doc.warnings.should be_empty
  end

  it "flags an off-spec @context URL" do
    doc = Vex::Document.new(id: "https://example.com/vex/w", author: "x")
    doc.context = "https://example.com/my-vex-context"
    doc.warnings.any?(&.includes?("openvex.dev")).should be_true
  end

  it "leaves an empty @context alone (validate handles that)" do
    doc = Vex::Document.from_json(%({"statements": []}))
    doc.warnings.any?(&.includes?("openvex.dev")).should be_false
  end

  it "surfaces product Appendix-A / Appendix-B warnings with index" do
    doc = Vex::Document.new(id: "https://example.com/vex/w", author: "x")
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(
        id: "pkg:x",
        hashes: {"sha-128" => "ab"},
        identifiers: {"oci" => "..."},
      )],
    ))
    msgs = doc.warnings.join("\n")
    msgs.should contain("statements[0].products[0]")
    msgs.should contain("Appendix A")
    msgs.should contain("Appendix B")
  end

  it "flags a non-IRI document @id" do
    doc = Vex::Document.new(id: "not-an-iri", author: "x")
    doc.warnings.any? { |w| w.includes?("@id") && w.includes?("not an IRI") }.should be_true
  end

  it "is silent on an https document @id" do
    doc = Vex::Document.new(id: "https://example.com/vex/x", author: "x")
    doc.warnings.any?(&.includes?("@id")).should be_false
  end

  it "is silent on a doc @id with a non-https scheme" do
    # Spec just says "IRI" — purl-style, urn:, did:, etc. all count.
    doc = Vex::Document.new(id: "urn:uuid:9fb3463de1b57", author: "x")
    doc.warnings.any?(&.includes?("@id")).should be_false
  end

  it "flags a non-IRI statement @id" do
    doc = Vex::Document.new(id: "https://example.com/vex/x", author: "x")
    doc.add_statement(Vex::Statement.new(
      id: "bare-string",
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x")],
    ))
    doc.warnings.any? { |w| w.includes?("statements[0]") && w.includes?("not an IRI") }.should be_true
  end

  it "flags a non-IRI vulnerability @id" do
    doc = Vex::Document.new(id: "https://example.com/vex/x", author: "x")
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X", id: "CVE-2024-1"),
      products: [Vex::Product.new(id: "pkg:x")],
    ))
    msgs = doc.warnings.join("\n")
    msgs.should contain("vulnerability")
    msgs.should contain("not an IRI")
  end

  it "flags a non-IRI product @id (purl missing pkg: scheme is a common mistake)" do
    doc = Vex::Document.new(id: "https://example.com/vex/x", author: "x")
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "generic/app@1.0.0")],
    ))
    doc.warnings.any? { |w| w.includes?("products[0]") && w.includes?("not an IRI") }.should be_true
  end

  it "flags a non-IRI statement supplier" do
    doc = Vex::Document.new(id: "https://example.com/vex/x", author: "x")
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x")],
      supplier: "Acme Corp",
    ))
    doc.warnings.any? { |w| w.includes?("supplier") && w.includes?("not an IRI") }.should be_true
  end

  it "is silent on an IRI statement supplier" do
    doc = Vex::Document.new(id: "https://example.com/vex/x", author: "x")
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x")],
      supplier: "https://acme.example",
    ))
    doc.warnings.any?(&.includes?("supplier")).should be_false
  end

  it "is silent on a purl product @id" do
    doc = Vex::Document.new(id: "https://example.com/vex/x", author: "x")
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:generic/app@1.0.0")],
    ))
    doc.warnings.should be_empty
  end

  it "surfaces subcomponent warnings with full index path" do
    doc = Vex::Document.new(id: "https://example.com/vex/w", author: "x")
    doc.add_statement(Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(
        id: "pkg:x",
        subcomponents: [
          Vex::Subcomponent.new(id: "pkg:y", hashes: {"sha-128" => "ab"}),
        ],
      )],
    ))
    doc.warnings.first.should contain("subcomponents[0]")
  end
end

describe "Document inheritance flow" do
  it "inherits a missing statement timestamp from the document" do
    doc_ts = Time.utc(2024, 1, 1)
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x")],
    )
    doc = Vex::Document.new(
      id: "https://example.com/vex/inh",
      author: "t",
      timestamp: doc_ts,
      statements: [stmt],
    )
    doc.effective_timestamp_for(stmt).should eq(doc_ts)
    doc.valid?.should be_true
  end

  it "statement-level timestamp overrides the document timestamp" do
    own = Time.utc(2024, 6, 1)
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x")],
      timestamp: own,
    )
    doc = Vex::Document.new(
      id: "https://example.com/vex/inh2",
      author: "t",
      timestamp: Time.utc(2024, 1, 1),
      statements: [stmt],
    )
    doc.effective_timestamp_for(stmt).should eq(own)
  end

  it "flags a statement with no effective timestamp" do
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [Vex::Product.new(id: "pkg:x")],
    )
    doc = Vex::Document.new(
      id: "https://example.com/vex/no-ts",
      author: "t",
      timestamp: nil,
      statements: [stmt],
    )
    doc.validate.any?(&.includes?("timestamp is required")).should be_true
  end

  it "flags a statement with missing products" do
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
    )
    doc = Vex::Document.new(
      id: "https://example.com/vex/no-prod",
      author: "t",
      statements: [stmt],
    )
    doc.validate.any?(&.includes?("products is required")).should be_true
  end

  it "flags a statement with an empty products array" do
    stmt = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
      products: [] of Vex::Product,
    )
    doc = Vex::Document.new(
      id: "https://example.com/vex/empty-prod",
      author: "t",
      statements: [stmt],
    )
    doc.validate.any?(&.includes?("products is required")).should be_true
  end
end

describe "Document.generate_canonical_id" do
  make_stmt = ->(vuln : String, prod : String) do
    Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: vuln),
      products: [Vex::Product.new(id: prod)],
    )
  end

  it "returns an openvex.dev/docs/ IRI" do
    id = Vex::Document.generate_canonical_id([make_stmt.call("CVE-1", "pkg:a")])
    id.starts_with?("#{Vex::PUBLIC_NAMESPACE}/vex-").should be_true
    id.size.should be > "#{Vex::PUBLIC_NAMESPACE}/vex-".size + 32
  end

  it "is stable across statement order" do
    a = make_stmt.call("CVE-A", "pkg:a")
    b = make_stmt.call("CVE-B", "pkg:b")
    Vex::Document.generate_canonical_id([a, b])
      .should eq(Vex::Document.generate_canonical_id([b, a]))
  end

  it "is stable across statement-level timestamps and status_notes" do
    s1 = make_stmt.call("CVE-X", "pkg:x")
    s2 = make_stmt.call("CVE-X", "pkg:x")
    s2.timestamp = Time.utc(2024, 6, 1)
    s2.status_notes = "added later"
    s2.last_updated = Time.utc(2025, 1, 1)
    # Same status + products + vuln name → same canonical ID even though
    # mutable bookkeeping fields differ. Lets consumers de-duplicate.
    Vex::Document.generate_canonical_id([s1])
      .should eq(Vex::Document.generate_canonical_id([s2]))
  end

  it "changes when product identifiers differ" do
    a = Vex::Document.generate_canonical_id([make_stmt.call("CVE-X", "pkg:a")])
    b = Vex::Document.generate_canonical_id([make_stmt.call("CVE-X", "pkg:b")])
    a.should_not eq(b)
  end

  it "changes when vulnerability aliases differ" do
    s1 = make_stmt.call("CVE-X", "pkg:a")
    s2 = make_stmt.call("CVE-X", "pkg:a")
    s2.vulnerability = Vex::Vulnerability.new(name: "CVE-X", aliases: ["GHSA-1"])
    Vex::Document.generate_canonical_id([s1])
      .should_not eq(Vex::Document.generate_canonical_id([s2]))
  end

  it "regenerate_id sets the @id deterministically from current statements" do
    doc = Vex::Document.new(id: "https://example.com/vex/placeholder", author: "t")
    doc.add_statement(make_stmt.call("CVE-Q", "pkg:q"))
    new_id = doc.regenerate_id
    doc.id.should eq(new_id)
    new_id.starts_with?("#{Vex::PUBLIC_NAMESPACE}/vex-").should be_true
  end

  it "recursive subcomponents participate in the canonical id" do
    nested = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-R"),
      products: [Vex::Product.new(
        id: "pkg:p",
        subcomponents: [Vex::Subcomponent.new(id: "pkg:s")],
      )],
    )
    flat = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-R"),
      products: [Vex::Product.new(id: "pkg:p")],
    )
    Vex::Document.generate_canonical_id([nested])
      .should_not eq(Vex::Document.generate_canonical_id([flat]))
  end
end

describe "Document.merge" do
  fixed = ->(vuln : String, prod : String, ts : Time?) do
    Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: vuln),
      products: [Vex::Product.new(id: prod)],
      timestamp: ts,
    )
  end

  it "unions disjoint statements in input order" do
    a = Vex::Document.new(id: "https://x/a", author: "t",
      statements: [fixed.call("CVE-A", "pkg:a", Time.utc(2024, 1, 1))])
    b = Vex::Document.new(id: "https://x/b", author: "t",
      statements: [fixed.call("CVE-B", "pkg:b", Time.utc(2024, 2, 1))])
    merged = Vex::Document.merge([a, b], id: "https://x/merged", author: "t")
    merged.statements.size.should eq(2)
    merged.statements[0].vulnerability.try(&.name).should eq("CVE-A")
    merged.statements[1].vulnerability.try(&.name).should eq("CVE-B")
  end

  it "deduplicates value-equal statements across inputs" do
    s = fixed.call("CVE-X", "pkg:x", Time.utc(2024, 1, 1))
    a = Vex::Document.new(id: "https://x/a", author: "t", statements: [s])
    b = Vex::Document.new(id: "https://x/b", author: "t", statements: [s.dup])
    merged = Vex::Document.merge([a, b], id: "https://x/m", author: "t")
    merged.statements.size.should eq(1)
  end

  it "preserves the full history when (product, vuln) appears in both" do
    older = fixed.call("CVE-H", "pkg:h", Time.utc(2024, 1, 1))
    newer = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-H"),
      products: [Vex::Product.new(id: "pkg:h")],
      timestamp: Time.utc(2024, 6, 1),
      status_notes: "regression in 2.0",
    )
    a = Vex::Document.new(id: "https://x/a", author: "t", statements: [older])
    b = Vex::Document.new(id: "https://x/b", author: "t", statements: [newer])
    merged = Vex::Document.merge([a, b], id: "https://x/m", author: "t")
    merged.statements.size.should eq(2)
    # `effective_statement` picks the newer one at lookup time.
    merged.effective_statement("pkg:h", "CVE-H").try(&.status_notes).should eq("regression in 2.0")
  end

  it "auto-generates a canonical @id when id is omitted" do
    a = Vex::Document.new(id: "https://x/a", author: "t",
      statements: [fixed.call("CVE-A", "pkg:a", nil)])
    b = Vex::Document.new(id: "https://x/b", author: "t",
      statements: [fixed.call("CVE-B", "pkg:b", nil)])
    merged = Vex::Document.merge([a, b], author: "t")
    merged.id.starts_with?("#{Vex::PUBLIC_NAMESPACE}/vex-").should be_true
  end

  it "instance #merge keeps receiver identity and bumps last_updated" do
    a = Vex::Document.new(id: "https://x/a", author: "alice", role: "Document Creator",
      statements: [fixed.call("CVE-A", "pkg:a", Time.utc(2024, 1, 1))])
    b = Vex::Document.new(id: "https://x/b", author: "bob",
      statements: [fixed.call("CVE-B", "pkg:b", Time.utc(2024, 2, 1))])
    merged = a.merge(b)
    merged.id.should eq("https://x/a")
    merged.author.should eq("alice")
    merged.role.should eq("Document Creator")
    merged.statements.size.should eq(2)
    merged.last_updated.should_not be_nil
  end
end

describe "Document#add_statement" do
  it "returns self for chaining" do
    doc = Vex::Document.new(id: "https://example.com/vex/chain", author: "x")
    chained = doc
      .add_statement(Vex::Statement.new(
        status: Vex::Status::Fixed,
        vulnerability: Vex::Vulnerability.new(name: "CVE-A"),
        products: [Vex::Product.new(id: "pkg:a")],
      ))
      .add_statement(Vex::Statement.new(
        status: Vex::Status::Fixed,
        vulnerability: Vex::Vulnerability.new(name: "CVE-B"),
        products: [Vex::Product.new(id: "pkg:b")],
      ))
    chained.should be(doc)
    doc.statements.size.should eq(2)
  end
end

describe "Document#effective_statement edge cases" do
  it "returns nil when no statement matches" do
    doc = Vex::Document.new(
      id: "https://example.com/vex/eff",
      author: "x",
      statements: [
        Vex::Statement.new(
          status: Vex::Status::Fixed,
          vulnerability: Vex::Vulnerability.new(name: "CVE-A"),
          products: [Vex::Product.new(id: "pkg:generic/a")],
        ),
      ],
    )
    doc.effective_statement("pkg:generic/b", "CVE-A").should be_nil
    doc.effective_statement("pkg:generic/a", "CVE-Z").should be_nil
  end

  it "matches a statement by vulnerability alias" do
    doc = Vex::Document.new(
      id: "https://example.com/vex/alias",
      author: "x",
      statements: [
        Vex::Statement.new(
          status: Vex::Status::Fixed,
          vulnerability: Vex::Vulnerability.new(
            name: "CVE-2024-1",
            aliases: ["GHSA-xxxx-yyyy-zzzz"],
          ),
          products: [Vex::Product.new(id: "pkg:generic/a")],
        ),
      ],
    )
    eff = doc.effective_statement("pkg:generic/a", "GHSA-xxxx-yyyy-zzzz")
    eff.should_not be_nil
  end

  it "matches a product by identifier value" do
    doc = Vex::Document.new(
      id: "https://example.com/vex/idmatch",
      author: "x",
      statements: [
        Vex::Statement.new(
          status: Vex::Status::Fixed,
          vulnerability: Vex::Vulnerability.new(name: "CVE-2024-1"),
          products: [
            Vex::Product.new(identifiers: {"purl" => "pkg:generic/a@1"}),
          ],
        ),
      ],
    )
    doc.effective_statement("pkg:generic/a@1", "CVE-2024-1").should_not be_nil
  end

  it "returns nil when the document has no statements" do
    doc = Vex::Document.new(id: "https://example.com/vex/empty", author: "x")
    doc.effective_statement("pkg:anything", "CVE-anything").should be_nil
  end

  it "find_statements returns every match in source order" do
    older = Vex::Statement.new(
      status: Vex::Status::UnderInvestigation,
      vulnerability: Vex::Vulnerability.new(name: "CVE-H"),
      products: [Vex::Product.new(id: "pkg:h")],
      timestamp: Time.utc(2024, 1, 1),
    )
    newer = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-H"),
      products: [Vex::Product.new(id: "pkg:h")],
      timestamp: Time.utc(2024, 6, 1),
    )
    unrelated = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-OTHER"),
      products: [Vex::Product.new(id: "pkg:h")],
    )
    doc = Vex::Document.new(
      id: "https://example.com/vex/hist",
      author: "t",
      statements: [older, unrelated, newer],
    )
    found = doc.find_statements("pkg:h", "CVE-H")
    found.size.should eq(2)
    found.first.should be(older)
    found.last.should be(newer)
  end

  it "find_statements returns [] when no statement matches" do
    doc = Vex::Document.new(
      id: "https://example.com/vex/no-match",
      author: "t",
      statements: [
        Vex::Statement.new(
          status: Vex::Status::Fixed,
          vulnerability: Vex::Vulnerability.new(name: "CVE-A"),
          products: [Vex::Product.new(id: "pkg:a")],
        ),
      ],
    )
    doc.find_statements("pkg:b", "CVE-A").should be_empty
    doc.find_statements("pkg:a", "CVE-Z").should be_empty
  end

  it "find_statements matches by alias and identifier value (parity with effective_statement)" do
    doc = Vex::Document.new(
      id: "https://example.com/vex/aliasmatch",
      author: "t",
      statements: [
        Vex::Statement.new(
          status: Vex::Status::Fixed,
          vulnerability: Vex::Vulnerability.new(
            name: "CVE-2024-1",
            aliases: ["GHSA-xxxx-yyyy-zzzz"],
          ),
          products: [
            Vex::Product.new(identifiers: {"purl" => "pkg:generic/a@1"}),
          ],
        ),
      ],
    )
    doc.find_statements("pkg:generic/a@1", "GHSA-xxxx-yyyy-zzzz").size.should eq(1)
  end

  it "ranks statements by inherited document timestamp when own is missing" do
    # Two statements, both without own timestamps. Ranking falls back to the
    # doc-level timestamp shared by both, so source order decides — last wins.
    older = Vex::Statement.new(
      status: Vex::Status::UnderInvestigation,
      vulnerability: Vex::Vulnerability.new(name: "CVE-INH"),
      products: [Vex::Product.new(id: "pkg:i")],
    )
    newer = Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-INH"),
      products: [Vex::Product.new(id: "pkg:i")],
    )
    doc = Vex::Document.new(
      id: "https://example.com/vex/inh-eff",
      author: "t",
      timestamp: Time.utc(2024, 1, 1),
      statements: [older, newer],
    )
    eff = doc.effective_statement("pkg:i", "CVE-INH")
    eff.try(&.status).should eq(Vex::Status::Fixed)
  end
end

describe "Vex::Vulnerability defensive behavior" do
  it "matches? returns false when all identifying fields are nil" do
    Vex::Vulnerability.new.matches?("anything").should be_false
    Vex::Vulnerability.new.matches?("").should be_false
  end

  it "equality distinguishes id-only vulnerabilities" do
    a = Vex::Vulnerability.new(id: "urn:a", name: "CVE-X")
    b = Vex::Vulnerability.new(id: "urn:b", name: "CVE-X")
    a.should_not eq(b)
  end

  it "equality distinguishes description-only differences" do
    a = Vex::Vulnerability.new(name: "CVE-X", description: "one")
    b = Vex::Vulnerability.new(name: "CVE-X", description: "two")
    a.should_not eq(b)
  end
end

describe "JSON round-trip with non-UTC offsets" do
  it "round-trips a full document with a -06:00 statement timestamp" do
    # The spec example uses fractional-second precision with a -06:00 offset;
    # verify the converter preserves the offset through a full Document
    # round-trip (not just a direct TimeConverter call).
    raw = <<-JSON
      {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/vex/offset",
        "author": "tester",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "statements": [
          {
            "timestamp": "2023-01-09T09:08:42-06:00",
            "vulnerability": {"name": "CVE-OFF"},
            "products": [{"@id": "pkg:o"}],
            "status": "fixed"
          }
        ]
      }
      JSON
    doc = Vex::Document.from_json(raw)
    doc.timestamp.try(&.offset).should eq(-6 * 3600)
    doc.statements.first.timestamp.try(&.offset).should eq(-6 * 3600)
    reparsed = Vex::Document.from_json(doc.to_json)
    reparsed.statements.first.timestamp.should eq(doc.statements.first.timestamp)
  end
end

describe "Vex::Product JSON shape" do
  it "emits an empty subcomponents array when explicitly set" do
    # Documents this surface so behavior changes show up in CI. The current
    # serializer omits a nil `subcomponents`, but emits `[]` when explicitly
    # set — useful for producers that want to signal "no subcomponents" vs
    # "unknown".
    p_nil = Vex::Product.new(id: "pkg:x")
    JSON.parse(p_nil.to_json).as_h.has_key?("subcomponents").should be_false

    p_empty = Vex::Product.new(id: "pkg:x", subcomponents: [] of Vex::Subcomponent)
    parsed = JSON.parse(p_empty.to_json).as_h
    parsed["subcomponents"].as_a.should be_empty
  end
end
