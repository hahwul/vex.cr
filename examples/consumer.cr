require "../src/vex"

# =============================================================================
# Consuming a VEX document
# =============================================================================
# Parse a JSON document, iterate over its statements, and ask whether a
# specific (product, vulnerability) pair is impacted using the most recent
# statement.

JSON_DOC = <<-JSON
  {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://example.com/vex/2025-001",
    "author": "security@example.com",
    "timestamp": "2025-01-15T09:00:00Z",
    "version": 2,
    "statements": [
      {
        "vulnerability": {"name": "CVE-2024-0001", "aliases": ["GHSA-aaaa-bbbb-cccc"]},
        "products": [{"@id": "pkg:generic/example@1.0.0"}],
        "status": "under_investigation",
        "timestamp": "2025-01-10T12:00:00Z"
      },
      {
        "vulnerability": {"name": "CVE-2024-0001"},
        "products": [{"@id": "pkg:generic/example@1.0.0"}],
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "timestamp": "2025-01-15T09:00:00Z"
      },
      {
        "vulnerability": {"name": "CVE-2024-0002"},
        "products": [{"@id": "pkg:generic/example@1.0.0"}],
        "status": "affected",
        "action_statement": "Upgrade to 1.1.0 or later."
      }
    ]
  }
  JSON

doc = Vex::Document.from_json(JSON_DOC)

puts "--- Document metadata ---"
puts "id:        #{doc.id}"
puts "author:    #{doc.author}"
puts "version:   #{doc.version}"
puts "timestamp: #{doc.timestamp}"

puts "\n--- All statements ---"
doc.statements.each_with_index do |stmt, i|
  vuln = stmt.vulnerability.try(&.name) || "<none>"
  product = stmt.products.try(&.first?.try(&.id)) || "<none>"
  puts "[#{i}] #{vuln} on #{product}: #{stmt.status}"
end

puts "\n--- Effective ruling for CVE-2024-0001 on pkg:generic/example@1.0.0 ---"
eff = doc.effective_statement("pkg:generic/example@1.0.0", "CVE-2024-0001")
if eff
  puts "status:    #{eff.status}"
  puts "issued at: #{eff.timestamp}"
  puts "reason:    #{eff.justification || eff.impact_statement || eff.action_statement || "n/a"}"
end

puts "\n--- Vulnerability lookup also works via alias ---"
eff_by_alias = doc.effective_statement("pkg:generic/example@1.0.0", "GHSA-aaaa-bbbb-cccc")
puts "Found via GHSA alias? #{!eff_by_alias.nil?}"
