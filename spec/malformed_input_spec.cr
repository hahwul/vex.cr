require "./spec_helper"

# Parsing untrusted VEX documents is the normal case — feeds arrive from
# upstream vendors, scanners, and hand-edited files. The contract these specs
# pin down is that every failure mode surfaces as `Vex::ParseError` (a
# `Vex::Error`), never as a raw stdlib leak like `TypeCastError`, `KeyError`,
# `NilAssertionError`, or an unwrapped `JSON::ParseException`.

MALFORMED_DOCUMENTS = {
  "truncated object"              => %({),
  "truncated array"               => %({"statements": [),
  "empty input"                   => "",
  "whitespace only"               => "   \n ",
  "top-level array"               => %([1, 2, 3]),
  "top-level string"              => %("nope"),
  "top-level null"                => %(null),
  "trailing garbage"              => %({"statements": []} oops),
  "statements is a string"        => %({"statements": "nope"}),
  "statement is a number"         => %({"statements": [7]}),
  "version is a string"           => %({"version": "one"}),
  "version overflows Int32"       => %({"version": 99999999999999}),
  "unknown status label"          => %({"statements": [{"status": "maybe"}]}),
  "status is a number"            => %({"statements": [{"status": 5}]}),
  "status is null"                => %({"statements": [{"status": null}]}),
  "unknown justification label"   => %({"statements": [{"status": "not_affected", "justification": "why"}]}),
  "vulnerability is a string"     => %({"statements": [{"status": "fixed", "vulnerability": "CVE-1"}]}),
  "aliases is a string"           => %({"statements": [{"status": "fixed", "vulnerability": {"aliases": "GHSA-1"}}]}),
  "products is an object"         => %({"statements": [{"status": "fixed", "products": {"@id": "pkg:a"}}]}),
  "hash value is a number"        => %({"statements": [{"status": "fixed", "products": [{"hashes": {"sha-256": 1}}]}]}),
  "identifiers is an array"       => %({"statements": [{"status": "fixed", "products": [{"identifiers": ["purl"]}]}]}),
  "subcomponents is a string"     => %({"statements": [{"status": "fixed", "products": [{"subcomponents": "inner"}]}]}),
  "document timestamp is garbage" => %({"timestamp": "yesterday", "statements": []}),
  "document timestamp is a bool"  => %({"timestamp": true, "statements": []}),
  "last_updated is garbage"       => %({"last_updated": "soon", "statements": []}),
  "statement timestamp garbage"   => %({"statements": [{"status": "fixed", "timestamp": "2025-13-45T99:99:99Z"}]}),
  "action timestamp garbage"      => %({"statements": [{"status": "affected", "action_statement_timestamp": "n/a"}]}),
}

describe "malformed input handling" do
  MALFORMED_DOCUMENTS.each do |label, payload|
    it "raises Vex::ParseError for #{label}" do
      expect_raises(Vex::ParseError) do
        Vex::Document.from_json(payload)
      end
    end
  end

  it "raises Vex::ParseError for a malformed standalone statement" do
    # The spec's "Encapsulating Document" section describes statements
    # travelling inside in-toto/CSAF/CycloneDX payloads, so a statement is a
    # parse entry point of its own and must honour the same contract.
    expect_raises(Vex::ParseError) do
      Vex::Statement.from_json(%({"status": "fixed", "products": ))
    end
  end

  it "surfaces every failure as a Vex::Error" do
    MALFORMED_DOCUMENTS.each_value do |payload|
      Vex::Document.from_json(payload)
      fail "expected #{payload.inspect} to raise"
    rescue ex : Vex::Error
      ex.should be_a(Vex::ParseError)
    end
  end

  it "keeps the underlying JSON exception as the cause" do
    Vex::Document.from_json(%({"statements": "nope"}))
    fail "expected a raise"
  rescue ex : Vex::ParseError
    ex.cause.should be_a(JSON::ParseException)
  end

  it "names the offending field in the message" do
    Vex::Document.from_json(%({"statements": [{"status": "maybe"}]}))
    fail "expected a raise"
  rescue ex : Vex::ParseError
    ex.message.to_s.should contain("maybe")
  end

  it "raises Vex::ParseError through from_file too" do
    path = File.tempname("vex-malformed", ".json")
    begin
      File.write(path, %({"statements": [{"status": "wobbly"}]}))
      expect_raises(Vex::ParseError, /wobbly/) do
        Vex::Document.from_file(path)
      end
    ensure
      File.delete(path) if File.exists?(path)
    end
  end

  it "reports a missing file as a filesystem error, not a parse error" do
    # A file that isn't there is not a malformed document; conflating the two
    # would hide an operator mistake behind a "bad VEX" message.
    expect_raises(File::NotFoundError) do
      Vex::Document.from_file(File.join(Dir.tempdir, "vex-does-not-exist-#{Random.rand(1_000_000)}.json"))
    end
  end
end

describe "structurally odd but parseable input" do
  # These are not errors: the parser is deliberately permissive so real feeds
  # load, with `validate` as the place that reports the spec gaps.

  it "accepts an explicit null statements array" do
    Vex::Document.from_json(%({"statements": null})).statements.should be_empty
  end

  it "accepts a document with no keys at all" do
    doc = Vex::Document.from_json(%({}))
    doc.statements.should be_empty
    doc.valid?.should be_false
  end

  it "ignores unknown keys at every nesting depth" do
    json = <<-JSON
      {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/vex/unknown-keys",
        "author": "a@example.com",
        "timestamp": "2025-01-01T00:00:00Z",
        "version": 1,
        "future_document_key": {"nested": [1, 2]},
        "statements": [
          {
            "status": "fixed",
            "future_statement_key": null,
            "vulnerability": {"name": "CVE-1", "future_vuln_key": 3},
            "products": [
              {"@id": "pkg:a", "future_component_key": ["x"],
               "subcomponents": [{"@id": "pkg:b", "future_sub_key": true}]}
            ]
          }
        ]
      }
      JSON
    doc = Vex::Document.from_json(json)
    doc.valid?.should be_true
    doc.statements.first.products.try(&.first.subcomponents.try(&.first.id)).should eq("pkg:b")
  end

  it "validates rather than raises on a deeply nested subcomponent tree" do
    depth = 60
    inner = %({"@id": "pkg:leaf"})
    depth.times { |i| inner = %({"@id": "pkg:n#{i}", "subcomponents": [#{inner}]}) }
    json = %({"statements": [{"status": "fixed", "vulnerability": {"name": "CVE-1"}, "products": [#{inner}]}]})

    doc = Vex::Document.from_json(json)
    doc.statements.first.validate.should be_empty
    doc.warnings.should be_empty
  end

  it "surfaces an unidentifiable component at the bottom of a deep tree" do
    depth = 40
    inner = %({})
    depth.times { |i| inner = %({"@id": "pkg:n#{i}", "subcomponents": [#{inner}]}) }
    json = %({"statements": [{"status": "fixed", "vulnerability": {"name": "CVE-1"}, "products": [#{inner}]}]})

    errors = Vex::Document.from_json(json).statements.first.validate
    errors.size.should eq(1)
    errors.first.should contain("has no @id, identifiers, or hashes")
    errors.first.scan("subcomponents[0]").size.should eq(depth)
  end

  it "keeps duplicated JSON keys parseable (last value wins)" do
    doc = Vex::Document.from_json(%({"@id": "https://a/1", "@id": "https://a/2", "statements": []}))
    doc.id.should eq("https://a/2")
  end
end

describe "enum and timestamp errors are the shard's own type" do
  it "Status.parse_wire raises Vex::ParseError" do
    expect_raises(Vex::ParseError, /invalid VEX status/) { Vex::Status.parse_wire("") }
  end

  it "Justification.parse_wire raises Vex::ParseError" do
    expect_raises(Vex::ParseError, /invalid VEX justification/) { Vex::Justification.parse_wire("") }
  end

  it "TimeConverter.parse raises Vex::ParseError" do
    expect_raises(Vex::ParseError, /Could not parse VEX timestamp/) { Vex::TimeConverter.parse("") }
  end

  it "Vex::ParseError is a Vex::Error" do
    Vex::ParseError.new("x").should be_a(Vex::Error)
    Vex::Error.new("x").should be_a(Exception)
  end
end
