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
