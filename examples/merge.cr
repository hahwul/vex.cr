require "../src/vex"

# =============================================================================
# Merging VEX documents + canonical @id generation
# =============================================================================
# Two common operational needs the library covers:
#
#   merge — combine VEX feeds from multiple sources. The resulting document
#           carries the full history; `effective_statement` selects the most
#           recent ruling at lookup time.
#   generate_canonical_id — derive a deterministic `@id` from the statements
#           themselves when you don't have an authoritative IRI to assign.

upstream = Vex::Document.new(
  id: "https://upstream.example/vex/jan",
  author: "upstream@example.com",
  timestamp: Time.utc(2024, 1, 1),
)
upstream.add_statement(
  Vex::Statement.new(
    status: Vex::Status::UnderInvestigation,
    vulnerability: Vex::Vulnerability.new(name: "CVE-2024-555"),
    products: [Vex::Product.new(id: "pkg:generic/app@1.0.0")],
    timestamp: Time.utc(2024, 1, 15),
  ),
)

internal = Vex::Document.new(
  id: "https://internal.example/vex/mar",
  author: "secops@example.com",
  timestamp: Time.utc(2024, 3, 1),
)
internal.add_statement(
  Vex::Statement.new(
    status: Vex::Status::Fixed,
    vulnerability: Vex::Vulnerability.new(name: "CVE-2024-555"),
    products: [Vex::Product.new(id: "pkg:generic/app@1.0.0")],
    timestamp: Time.utc(2024, 3, 12),
    status_notes: "patched in 1.0.1",
  ),
)

# Combine. With no `id:`, the merged document gets a canonical @id derived
# from the union of statements — stable across input order, so a re-run
# producing the same data produces the same ID.
combined = Vex::Document.merge([upstream, internal], author: "release-eng@example.com")
puts "Merged @id: #{combined.id}"
puts "Statements: #{combined.statements.size}"

# The history is preserved; effective_statement picks the most recent ruling.
eff = combined.effective_statement("pkg:generic/app@1.0.0", "CVE-2024-555")
puts "Current status: #{eff.try(&.status)}"
puts "Audit trail   : #{combined.find_statements("pkg:generic/app@1.0.0", "CVE-2024-555").map(&.status).join(" -> ")}"

# Instance #merge keeps the receiver's identity (id/author/role) and bumps
# last_updated — convenient when one document is "yours" and you're folding
# in a feed from elsewhere.
my_view = upstream.merge(internal)
puts "After folding in upstream: my @id stays #{my_view.id == upstream.id}; last_updated set #{!my_view.last_updated.nil?}"
