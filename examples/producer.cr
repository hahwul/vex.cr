require "../src/vex"

# =============================================================================
# Producing a VEX document
# =============================================================================
# Build a document with a mix of statuses to show the conditional fields each
# status takes:
#   not_affected        — requires justification or impact_statement
#   affected            — requires action_statement
#   fixed               — accepts status_notes; rejects justification/impact_statement
#   under_investigation — accepts status_notes; rejects justification/impact_statement

doc = Vex::Document.new(
  id: "https://example.com/vex/2025-001",
  author: "security@example.com",
  role: "Document Creator",
  tooling: "vex.cr/#{Vex::VERSION}",
)

doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::NotAffected,
    vulnerability: Vex::Vulnerability.new(
      name: "CVE-2024-0001",
      aliases: ["GHSA-aaaa-bbbb-cccc"],
    ),
    products: [Vex::Product.new(id: "pkg:generic/example@1.0.0")],
    justification: Vex::Justification::VulnerableCodeNotInExecutePath,
  ),
)

doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::Affected,
    vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0002"),
    products: [Vex::Product.new(id: "pkg:generic/example@1.0.0")],
    action_statement: "Upgrade to 1.1.0 or later.",
  ),
)

doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::Fixed,
    vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0003"),
    products: [Vex::Product.new(id: "pkg:generic/example@1.1.0")],
  ),
)

puts "--- valid? ---"
puts doc.valid? # => true

puts "\n--- to_json_pretty ---"
puts doc.to_json_pretty
