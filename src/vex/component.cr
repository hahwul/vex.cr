require "json"

module Vex
  # Component captures the fields shared by Product and Subcomponent.
  # Subclasses (Product) add extra fields; on the wire there is no Component
  # type — only `product` and `subcomponent` shapes that share these keys.
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

    def initialize(
      @id : String? = nil,
      @identifiers : Hash(String, String)? = nil,
      @hashes : Hash(String, String)? = nil,
    )
    end

    def matches?(identifier : String) : Bool
      return true if @id == identifier
      @identifiers.try &.each_value { |v| return true if v == identifier }
      false
    end

    # A component is identifiable when it carries at least one of `@id`,
    # `identifiers`, or `hashes`. Spec: "Product details MUST include
    # [product_id]" — and subcomponents inherit the same requirement from
    # the Component fields table.
    def identified? : Bool
      return true if @id
      return true if (ids = @identifiers) && !ids.empty?
      return true if (hs = @hashes) && !hs.empty?
      false
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

    def_equals_and_hash @id, @identifiers, @hashes
  end

  class Subcomponent < Component
  end

  class Product < Component
    @[JSON::Field(ignore_serialize: subcomponents.nil?)]
    property subcomponents : Array(Subcomponent)?

    def initialize(
      id : String? = nil,
      identifiers : Hash(String, String)? = nil,
      hashes : Hash(String, String)? = nil,
      @subcomponents : Array(Subcomponent)? = nil,
    )
      super(id: id, identifiers: identifiers, hashes: hashes)
    end

    def_equals_and_hash @id, @identifiers, @hashes, @subcomponents
  end
end
