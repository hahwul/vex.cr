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

describe Vex::Status do
  it "round-trips wire values" do
    Vex::Status::NotAffected.wire_value.should eq("not_affected")
    Vex::Status::UnderInvestigation.wire_value.should eq("under_investigation")
    Vex::Status.parse_wire("affected").should eq(Vex::Status::Affected)
  end

  it "serializes/deserializes via JSON" do
    json = Vex::Status::NotAffected.to_json
    json.should eq(%("not_affected"))
    Vex::Status.from_json(%("fixed")).should eq(Vex::Status::Fixed)
  end

  it "raises on unknown value" do
    expect_raises(ArgumentError, /invalid VEX status/) do
      Vex::Status.parse_wire("bogus")
    end
  end
end

describe Vex::Justification do
  it "round-trips wire values" do
    Vex::Justification::ComponentNotPresent.wire_value.should eq("component_not_present")
    Vex::Justification::VulnerableCodeCannotBeControlledByAdversary.wire_value
      .should eq("vulnerable_code_cannot_be_controlled_by_adversary")
    Vex::Justification.parse_wire("inline_mitigations_already_exist")
      .should eq(Vex::Justification::InlineMitigationsAlreadyExist)
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

  it "parses simple UTC timestamps" do
    t = Vex::TimeConverter.parse("2024-05-10T12:34:56Z")
    t.year.should eq(2024)
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
end
