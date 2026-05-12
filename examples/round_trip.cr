require "../src/vex"

# =============================================================================
# JSON round-trip via the filesystem
# =============================================================================
# Build a document, write it to disk, read it back, and confirm the parsed
# value matches the original. Demonstrates Document#write / .from_file.

original = Vex::Document.new(
  id: "https://example.com/vex/round-trip",
  author: "round-trip-demo",
  timestamp: Time.utc(2025, 5, 12, 10, 0, 0, nanosecond: 123_456_789),
)

original.add_statement(
  Vex::Statement.new(
    status: Vex::Status::NotAffected,
    vulnerability: Vex::Vulnerability.new(
      name: "CVE-2024-0007",
      id: "https://nvd.nist.gov/vuln/detail/CVE-2024-0007",
      aliases: ["GHSA-rrrr-tttt-uuuu"],
    ),
    products: [
      Vex::Product.new(
        id: "pkg:generic/demo@1.0.0",
        identifiers: {"purl" => "pkg:generic/demo@1.0.0"},
        hashes: {"sha-256" => "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        subcomponents: [
          Vex::Subcomponent.new(id: "pkg:generic/inner-lib@0.2.1"),
        ],
      ),
    ],
    justification: Vex::Justification::ComponentNotPresent,
  ),
)

path = File.tempname("vex-demo", ".json")

begin
  original.write(path)
  puts "Wrote document to: #{path}"
  puts "File size:         #{File.size(path)} bytes"

  loaded = Vex::Document.from_file(path)

  puts "\n--- Spot-checking the round-trip ---"
  puts "ids match:         #{loaded.id == original.id}"
  puts "timestamps match:  #{loaded.timestamp == original.timestamp}"
  puts "statement count:   #{loaded.statements.size}"
  puts "vuln aliases:      #{loaded.statements.first.vulnerability.try(&.aliases)}"
  puts "subcomponent id:   #{loaded.statements.first.products.try(&.first.subcomponents.try(&.first.id))}"
  puts "validates clean:   #{loaded.valid?}"
ensure
  File.delete(path) if File.exists?(path)
end
