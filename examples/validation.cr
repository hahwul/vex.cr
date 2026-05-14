require "../src/vex"

# =============================================================================
# Validating and inspecting a VEX document
# =============================================================================
# Three layers of feedback are surfaced on a document:
#
#   validate  — spec MUST violations (status conditional fields, missing
#               required fields, duplicate statement @ids, ...). These make
#               the document non-conformant.
#   warnings  — spec SHOULD advisories (non-IRI @id slots, hash algorithms
#               outside Appendix A, identifier types outside Appendix B,
#               off-spec @context URL, supplier that isn't an IRI). The
#               document is still `valid?` true.
#   find_statements / effective_statement — query helpers for downstream
#               consumers walking the statements.

# A document that's *almost* right: it has a clean structure but mistakes a
# bare CVE name for an IRI, drops a justification onto a `fixed` statement,
# and gives the supplier as a plain company name.
# An explicit doc timestamp gives statements without their own timestamp a
# fixed inheritance anchor — important for effective_statement, which falls
# back to the document timestamp when ranking ties.
doc = Vex::Document.new(
  id: "https://example.com/vex/2025-100",
  author: "security@example.com",
  timestamp: Time.utc(2025, 1, 1),
)

doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::Fixed,
    vulnerability: Vex::Vulnerability.new(
      name: "CVE-2024-0010",
      id: "CVE-2024-0010", # should be an IRI like https://nvd.nist.gov/...
    ),
    products: [Vex::Product.new(id: "pkg:generic/example@1.1.0")],
    justification: Vex::Justification::ComponentNotPresent, # stray on `fixed`
    supplier: "Acme Corp",                                  # not an IRI
  ),
)

doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::NotAffected,
    vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0010"),
    products: [Vex::Product.new(id: "pkg:generic/example@1.0.0")],
    justification: Vex::Justification::VulnerableCodeNotInExecutePath,
    timestamp: Time.utc(2025, 1, 5),
  ),
)

doc.add_statement(
  Vex::Statement.new(
    status: Vex::Status::Fixed,
    vulnerability: Vex::Vulnerability.new(name: "CVE-2024-0010"),
    products: [Vex::Product.new(id: "pkg:generic/example@1.1.0")],
    timestamp: Time.utc(2025, 2, 1),
  ),
)

puts "--- validate (MUST violations) ---"
errors = doc.validate
errors.each { |e| puts "  ERROR: #{e}" }
puts "  valid? #{doc.valid?}"

puts "\n--- warnings (SHOULD advisories) ---"
doc.warnings.each { |w| puts "  WARN:  #{w}" }

# Query helpers — find_statements returns every match in source order, while
# effective_statement applies the spec's timestamp-then-source-order ranking
# to surface the single most recent ruling.
purl = "pkg:generic/example@1.1.0"
cve = "CVE-2024-0010"

puts "\n--- find_statements(#{purl.inspect}, #{cve.inspect}) ---"
doc.find_statements(purl, cve).each_with_index do |s, i|
  effective_ts = doc.effective_timestamp_for(s)
  puts "  [#{i}] status=#{s.status} effective_timestamp=#{effective_ts}"
end

puts "\n--- effective_statement(#{purl.inspect}, #{cve.inspect}) ---"
eff = doc.effective_statement(purl, cve)
if eff
  puts "  status=#{eff.status} effective_timestamp=#{doc.effective_timestamp_for(eff)}"
end
