require "json"
require "./version"
require "./statement"
require "./time_format"

module Vex
  class Document
    include JSON::Serializable

    # Required fields per the OpenVEX spec are declared with defaults so we
    # can still parse real-world documents that omit them (matching go-vex's
    # tolerance — its testdata/v020-*.vex.json fixtures omit `version` and
    # would otherwise fail). Use `valid?` / `validate` to surface the gap.

    @[JSON::Field(key: "@context")]
    property context : String = ""

    @[JSON::Field(key: "@id")]
    property id : String = ""

    property author : String = ""

    @[JSON::Field(ignore_serialize: role.nil?)]
    property role : String?

    @[JSON::Field(converter: Vex::TimeConverter, ignore_serialize: timestamp.nil?)]
    property timestamp : Time?

    @[JSON::Field(key: "last_updated", converter: Vex::TimeConverter, ignore_serialize: last_updated.nil?)]
    property last_updated : Time?

    property version : Int32 = 0

    @[JSON::Field(ignore_serialize: tooling.nil?)]
    property tooling : String?

    @[JSON::Field(ignore_serialize: supplier.nil?)]
    property supplier : String?

    property statements : Array(Statement) = [] of Statement

    def initialize(
      @id : String,
      @author : String = DEFAULT_AUTHOR,
      @statements : Array(Statement) = [] of Statement,
      @version : Int32 = 1,
      @context : String = CONTEXT,
      @timestamp : Time? = Time.utc,
      @last_updated : Time? = nil,
      @role : String? = nil,
      @tooling : String? = nil,
      @supplier : String? = nil,
    )
    end

    def add_statement(statement : Statement) : self
      @statements << statement
      self
    end

    # Returns validation errors for the document. The document is valid if
    # every statement is valid and required document-level fields are present.
    def validate : Array(String)
      errors = [] of String
      errors << "@context must not be empty" if context.empty?
      errors << "@id must not be empty" if id.empty?
      errors << "author must not be empty" if author.empty?
      errors << "version must be >= 1" if version < 1

      # Spec: statement @id "must be unique for each statement in the document".
      seen_ids = Set(String).new
      statements.each_with_index do |stmt, i|
        if sid = stmt.id
          if seen_ids.includes?(sid)
            errors << "statements[#{i}]: duplicate @id #{sid.inspect}"
          else
            seen_ids << sid
          end
        end
        stmt.validate.each do |err|
          errors << "statements[#{i}]: #{err}"
        end
      end
      errors
    end

    def valid? : Bool
      validate.empty?
    end

    # Returns the most recent statement for the given product/vuln identifier
    # pair. Compares timestamps with the document timestamp as fallback. Ties
    # resolve to the last statement in source order — matching go-vex, which
    # stable-sorts ascending then iterates from the end. This honors the
    # conceptual model that newer statements (those appended later) override
    # older ones when their timestamps cannot.
    def effective_statement(product : String, vulnerability : String) : Statement?
      doc_ts = @timestamp
      matching = statements.select do |s|
        next false unless s.vulnerability.try &.matches?(vulnerability)
        s.products.try(&.any? { |p| p.matches?(product) }) || false
      end
      return nil if matching.empty?
      matching.reverse.max_by { |s| (s.timestamp || doc_ts || Time::UNIX_EPOCH).to_unix_ns }
    end

    def to_json_pretty : String
      String.build do |io|
        JSON.build(io, indent: "  ") { |j| to_json(j) }
      end
    end

    # Reads a VEX document from disk. Strips a leading UTF-8 BOM if present
    # — Windows-emitted JSON often carries one, and Crystal's JSON parser is
    # strict about leading whitespace/markers.
    def self.from_file(path : String) : Document
      raw = File.read(path)
      raw = raw.lchop("\u{FEFF}")
      Document.from_json(raw)
    end

    def write(path : String) : Nil
      File.write(path, to_json_pretty)
    end

    def_equals_and_hash @context, @id, @author, @role, @timestamp, @last_updated,
      @version, @tooling, @supplier, @statements
  end
end
