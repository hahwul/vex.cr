require "uri"

module Vex
  VERSION = "0.1.0"

  # Pragmatic IRI check: a non-empty value whose URI form parses with a
  # non-empty scheme. We don't validate the full RFC 3987 grammar — that
  # would over-reject legitimate values. The scheme check catches the
  # common producer mistake of dropping a bare CVE name, package
  # version, or hash into a field that the spec says is an IRI.
  def self.iri_like?(value : String) : Bool
    return false if value.empty?
    scheme = URI.parse(value).scheme
    !scheme.nil? && !scheme.empty?
  rescue URI::Error
    # Crystal's URI.parse is lenient and returns a nil-scheme URI rather
    # than raising on most malformed inputs, but we keep the rescue as a
    # defensive belt-and-suspenders measure for stdlib changes.
    false
  end

  SPEC_VERSION = "0.2.0"

  CONTEXT = "https://openvex.dev/ns/v#{SPEC_VERSION}"

  # Spec: `@context` is structured as `https://openvex.dev/ns/v[version]`,
  # with the version optional (defaulting to v0.0.1 when omitted).
  CONTEXT_PATTERN = /\Ahttps:\/\/openvex\.dev\/ns(?:\/v\d+(?:\.\d+)*)?\z/

  PUBLIC_NAMESPACE = "https://openvex.dev/docs"

  DEFAULT_AUTHOR = "Unknown Author"

  # Spec Appendix A: Hash Names Table.
  KNOWN_HASH_LABELS = %w[
    md5 sha1 sha-256 sha-384 sha-512
    sha3-224 sha3-256 sha3-384 sha3-512
    blake2s-256 blake2b-256 blake2b-512
  ]

  # Spec Appendix B: Software Identifier Types Table.
  KNOWN_IDENTIFIER_LABELS = %w[purl cpe22 cpe23]
end
