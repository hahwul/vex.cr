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

  it "raises on a timestamp missing a timezone" do
    expect_raises(Time::Format::Error, /Could not parse/) do
      Vex::TimeConverter.parse("2024-05-10T12:34:56")
    end
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
      supplier: "https://example.com",
      timestamp: Time.utc(2025, 3, 1),
      last_updated: Time.utc(2025, 3, 2),
      version: 7,
    )
    reparsed = Vex::Document.from_json(doc.to_json)
    reparsed.role.should eq("Document Creator")
    reparsed.tooling.should eq("vex.cr/#{Vex::VERSION}")
    reparsed.supplier.should eq("https://example.com")
    reparsed.last_updated.should eq(Time.utc(2025, 3, 2))
    reparsed.version.should eq(7)
  end

  it "omits optional document fields when unset" do
    doc = Vex::Document.new(id: "https://example.com/vex/min", author: "x")
    parsed = JSON.parse(doc.to_json).as_h
    parsed.has_key?("role").should be_false
    parsed.has_key?("tooling").should be_false
    parsed.has_key?("supplier").should be_false
    parsed.has_key?("last_updated").should be_false
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

  it "round-trips supplier on a component" do
    c = Vex::Component.new(id: "pkg:generic/x", supplier: "https://example.com")
    parsed = Vex::Component.from_json(c.to_json)
    parsed.supplier.should eq("https://example.com")
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
end

describe "Statement#validate edge cases" do
  it "treats Fixed status as always valid" do
    Vex::Statement.new(
      status: Vex::Status::Fixed,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
    ).valid?.should be_true
  end

  it "treats UnderInvestigation status as always valid" do
    Vex::Statement.new(
      status: Vex::Status::UnderInvestigation,
      vulnerability: Vex::Vulnerability.new(name: "CVE-X"),
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
end
