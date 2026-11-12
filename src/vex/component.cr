require "json"
require "purl"

module Vex
  # go-vex `PurlMatches`: true when *general* matches the more specific
  # *specific* purl. Type, namespace and name must be equal (after purl.cr's
  # per-type normalization); a *general* without a version matches any
  # version, and every qualifier on *general* must be on *specific* with the
  # same value. Subpaths are ignored, and a purl purl.cr rejects matches
  # nothing. purl.cr enforces ECMA-427 per-type rules, so a spec-invalid purl
  # such as `pkg:golang/stdlib` (golang requires a namespace) only matches
  # by exact string, where go-vex's lenient parser would match it.
  def self.purl_matches?(general : String, specific : String) : Bool
    p1 = Purl::PackageURL.parse(general)
    p2 = Purl::PackageURL.parse(specific)
    return false unless p1.type == p2.type && p1.namespace == p2.namespace && p1.name == p2.name
    if v1 = p1.version.presence
      return false unless v1 == p2.version
    end
    return true unless q1 = p1.qualifiers
    q2 = p2.qualifiers
    q1.all? { |k, v| q2.try(&.[k]?) == v }
  rescue Purl::Error
    false
  end

  # Component captures the fields shared by Product and Subcomponent.
  # On the wire there is no Component type — only `product` and `subcomponent`
  # shapes that share these keys. The spec lists `subcomponents` as a Component
  # field, so a subcomponent can itself nest further subcomponents.
  class Component
    include JSON::Serializable

    # IRI identifying the component (recommended: a Package URL).
    @[JSON::Field(key: "@id", ignore_serialize: id.nil?)]
    property id : String?

    # Cryptographic hashes keyed by algorithm (sha-256, sha-512, ...).
    @[JSON::Field(ignore_serialize: hashes.nil?)]
    property hashes : Hash(String, String)?

    # Software identifiers keyed by type (purl, cpe22, cpe23).
    @[JSON::Field(ignore_serialize: identifiers.nil?)]
    property identifiers : Hash(String, String)?

    # Nested subcomponents. The spec defines `subcomponents` on Component, so
    # this is available on both Product and Subcomponent (allowing nesting).
    @[JSON::Field(ignore_serialize: subcomponents.nil?)]
    property subcomponents : Array(Subcomponent)?

    def initialize(
      @id : String? = nil,
      @identifiers : Hash(String, String)? = nil,
      @hashes : Hash(String, String)? = nil,
      @subcomponents : Array(Subcomponent)? = nil,
    )
    end

    # True when this component's `@id`, any identifier, or any hash value
    # equals *identifier* (go-vex `Component.Matches`). A purl `@id` or
    # `identifiers["purl"]` also matches a more specific purl: a product purl
    # without a version matches any version, and its qualifiers must all be
    # present in the query (see `Vex.purl_matches?`). Subcomponents are not
    # consulted; use `Product#matches?(identifier, subcomponent)`.
    def matches?(identifier : String) : Bool
      purl_query = identifier.starts_with?("pkg:")
      if (i = @id) && !i.empty?
        return true if i == identifier
        return true if purl_query && i.starts_with?("pkg:") && Vex.purl_matches?(i, identifier)
      end
      # ponytail: reparses both purls per comparison; parse the query once
      # per lookup if large documents make this hot.
      @identifiers.try &.each do |type, v|
        return true if v == identifier
        return true if purl_query && type == "purl" && Vex.purl_matches?(v, identifier)
      end
      @hashes.try &.each_value { |v| return true if v == identifier }
      false
    end

    # A component is identifiable when it carries at least one of `@id`,
    # `identifiers`, or `hashes`. Spec: "Product details MUST include
    # [product_id]" — and subcomponents inherit the same requirement from
    # the Component fields table. Empty strings identify nothing, so
    # `{"@id": ""}` or `{"identifiers": {"purl": ""}}` does not count.
    def identified? : Bool
      return true if (i = @id) && !i.empty?
      return true if @identifiers.try &.each_value.any? { |v| !v.empty? }
      @hashes.try(&.each_value.any? { |v| !v.empty? }) || false
    end

    # Spec-recommended keys are listed in Appendix A (hashes) and Appendix B
    # (identifiers). Unrecognized keys are not errors — the spec uses SHOULD
    # — but tooling consuming the document may not know how to interpret
    # them. Returns one warning string per unrecognized key, plus an
    # @id-not-an-IRI warning when the @id lacks a scheme (e.g. a bare purl
    # missing its `pkg:` prefix, or a CVE name in the wrong slot).
    def warnings : Array(String)
      out = [] of String
      if (i = @id) && !Vex.iri_like?(i)
        out << "@id #{i.inspect} is not an IRI (missing scheme)"
      end
      @hashes.try &.each_key do |k|
        out << "hash algorithm #{k.inspect} is not in Appendix A" unless KNOWN_HASH_LABELS.includes?(k)
      end
      @identifiers.try &.each_key do |k|
        out << "identifier type #{k.inspect} is not in Appendix B" unless KNOWN_IDENTIFIER_LABELS.includes?(k)
      end
      out
    end

    def_equals_and_hash @id, @identifiers, @hashes, @subcomponents
  end

  class Subcomponent < Component
  end

  class Product < Component
    # go-vex `Product.Matches`: the product itself must match *identifier*.
    # When a *subcomponent* is given and the product lists subcomponents, one
    # of its direct subcomponents must match it too (go-vex and the spec model
    # one level). A query naming only a subcomponent does not match: the
    # statement asserts the product's status.
    def matches?(identifier : String, subcomponent : String) : Bool
      return false unless matches?(identifier)
      subs = @subcomponents
      return true if subs.nil? || subs.empty? || subcomponent.empty?
      subs.any?(&.matches?(subcomponent))
    end
  end
end
