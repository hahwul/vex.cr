require "json"
require "digest/sha256"
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
      # Spec Document Struct Fields table marks `timestamp` as required at
      # the document level. The constructor defaults to `Time.utc`, so this
      # only fires for documents parsed from JSON where the key was absent
      # *and* the value wasn't repopulated — go-vex-style permissive parse,
      # strict validate.
      errors << "timestamp must be set at the document level" if @timestamp.nil?

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

        # Spec "Data Inheritance": a statement is incomplete (and the document
        # invalid) unless it effectively has a timestamp and products — own or
        # inherited from this document. Standalone OpenVEX has no encapsulating
        # document, so products without statement-level data is unrecoverable.
        if effective_timestamp_for(stmt).nil?
          errors << "statements[#{i}]: timestamp is required (own or inherited from document)"
        end
        prods = effective_products_for(stmt)
        if prods.nil? || prods.empty?
          errors << "statements[#{i}]: products is required and must be non-empty"
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

    # Returns non-fatal spec advisories — issues the spec marks as SHOULD
    # rather than MUST. Currently covers:
    #   * `@context` URLs that don't match the openvex.dev namespace
    #   * hash algorithms outside Appendix A
    #   * identifier types outside Appendix B
    # A document with warnings is still `valid?` true; tools that want a
    # stricter posture can fail on `warnings.any?` as their own policy.
    def warnings : Array(String)
      out = [] of String
      unless context.empty? || CONTEXT_PATTERN.matches?(context)
        out << "@context #{context.inspect} is not an openvex.dev namespace URL"
      end
      unless id.empty? || Vex.iri_like?(id)
        out << "@id #{id.inspect} is not an IRI (missing scheme)"
      end
      statements.each_with_index do |stmt, i|
        if (sid = stmt.id) && !Vex.iri_like?(sid)
          out << "statements[#{i}]: @id #{sid.inspect} is not an IRI (missing scheme)"
        end
        if (sup = stmt.supplier) && !Vex.iri_like?(sup)
          out << "statements[#{i}]: supplier #{sup.inspect} is not an IRI (missing scheme)"
        end
        stmt.vulnerability.try &.warnings.each do |w|
          out << "statements[#{i}].vulnerability: #{w}"
        end
        stmt.products.try &.each_with_index do |product, pi|
          base = "statements[#{i}].products[#{pi}]"
          product.warnings.each { |w| out << "#{base}: #{w}" }
          walk_component_tree(product, base) do |sub, path|
            sub.warnings.each { |w| out << "#{path}: #{w}" }
          end
        end
      end
      out
    end

    # Returns the effective timestamp for a statement, following the spec's
    # inheritance flow: a statement-level timestamp wins, otherwise the
    # document-level timestamp is inherited.
    def effective_timestamp_for(stmt : Statement) : Time?
      stmt.timestamp || @timestamp
    end

    # Returns the effective products for a statement. Standalone OpenVEX has
    # no encapsulating document, so this is just the statement's own
    # `products` field — exposed as a helper for symmetry with
    # `effective_timestamp_for` and so callers don't have to remember the
    # inheritance semantics when wiring documents together.
    def effective_products_for(stmt : Statement) : Array(Product)?
      stmt.products
    end

    # Returns all statements that mention the given (product, vuln) pair, in
    # source order. Useful for audit trails — "show me the full history of
    # how this product was assessed against this CVE." For the single most
    # recent ruling, use `effective_statement`.
    def find_statements(product : String, vulnerability : String) : Array(Statement)
      statements.select do |s|
        next false unless s.vulnerability.try &.matches?(vulnerability)
        s.products.try(&.any?(&.matches?(product))) || false
      end
    end

    # Returns the most recent statement for the given product/vuln identifier
    # pair. Compares timestamps with the document timestamp as fallback. Ties
    # resolve to the last statement in source order — matching go-vex, which
    # stable-sorts ascending then iterates from the end. This honors the
    # conceptual model that newer statements (those appended later) override
    # older ones when their timestamps cannot.
    def effective_statement(product : String, vulnerability : String) : Statement?
      matching = find_statements(product, vulnerability)
      return if matching.empty?
      matching.reverse.max_by { |s| (effective_timestamp_for(s) || Time::UNIX_EPOCH).to_unix_ns }
    end

    # Pre-order traversal of a component's subcomponent tree. Used by
    # `warnings` to surface advisories at any depth.
    private def walk_component_tree(component : Component, prefix : String, &block : Subcomponent, String ->) : Nil
      component.subcomponents.try &.each_with_index do |sub, i|
        path = "#{prefix}.subcomponents[#{i}]"
        block.call(sub, path)
        walk_component_tree(sub, path, &block)
      end
    end

    # Generates a deterministic IRI for a set of statements. The output is
    # stable across statement order so two callers assembling the same data
    # in different order receive the same `@id` — the property that lets
    # consumers de-duplicate documents.
    #
    # The hash covers each statement's vulnerability name (and id+aliases if
    # present), status, justification, action_statement, and the recursive
    # set of product/subcomponent identifiers. Mutable metadata like
    # `last_updated`, `status_notes`, and statement-level timestamps is
    # excluded so equivalent updates don't churn the document ID.
    def self.generate_canonical_id(statements : Array(Statement)) : String
      lines = statements.map { |s| canonical_statement_line(s) }.sort!
      sha = Digest::SHA256.hexdigest(lines.join("\n"))
      "#{PUBLIC_NAMESPACE}/vex-#{sha}"
    end

    # Recomputes and sets `@id` from the current statements. Useful after
    # building a document via `add_statement` if you didn't supply an `@id`.
    # The new value is returned for chaining.
    def regenerate_id : String
      @id = Document.generate_canonical_id(@statements)
    end

    private def self.canonical_statement_line(stmt : Statement) : String
      vuln = stmt.vulnerability
      parts = [
        "vuln=" + (vuln.try(&.name) || ""),
        "vid=" + (vuln.try(&.id) || ""),
        "aliases=" + (vuln.try(&.aliases).try(&.sort.join(",")) || ""),
        "status=" + stmt.status.wire_value,
        "just=" + (stmt.justification.try(&.wire_value) || ""),
        "impact=" + (stmt.impact_statement || ""),
        "action=" + (stmt.action_statement || ""),
        "supplier=" + (stmt.supplier || ""),
        "products=" + canonical_components(stmt.products),
      ]
      parts.join("|")
    end

    private def self.canonical_components(components : Array(Component)?) : String
      return "" if components.nil?
      components.map { |c| canonical_component(c) }.sort!.join(",")
    end

    private def self.canonical_component(component : Component) : String
      ids = [] of String
      ids << "@id=#{component.id}" if component.id
      component.identifiers.try &.to_a.sort_by { |(k, _)| k }.each do |(k, v)|
        ids << "#{k}=#{v}"
      end
      component.hashes.try &.to_a.sort_by { |(k, _)| k }.each do |(k, v)|
        ids << "h:#{k}=#{v}"
      end
      sub = canonical_components(component.subcomponents.try &.map(&.as(Component)))
      ids << "subs=[#{sub}]" unless sub.empty?
      "{#{ids.sort.join(";")}}"
    end

    # Combines multiple documents into one, preserving each statement's
    # source order across the inputs. Value-equal statements are deduplicated
    # — useful when feeds overlap on identical assertions. Per the spec,
    # statements are not collapsed by (product, vuln): the resulting document
    # carries the full history, and `effective_statement` selects the most
    # recent ruling at lookup time.
    #
    # The result inherits no metadata from the inputs by default; pass
    # `id:`, `author:`, etc. to set them explicitly. When `id:` is empty,
    # an `@id` is generated canonically from the merged statements.
    def self.merge(
      docs : Enumerable(Document),
      id : String = "",
      author : String = DEFAULT_AUTHOR,
      role : String? = nil,
      timestamp : Time? = Time.utc,
      tooling : String? = nil,
    ) : Document
      seen = Set(Statement).new
      merged = [] of Statement
      docs.each do |doc|
        doc.statements.each do |stmt|
          next if seen.includes?(stmt)
          seen << stmt
          merged << stmt
        end
      end
      effective_id = id.empty? ? generate_canonical_id(merged) : id
      Document.new(
        id: effective_id,
        author: author,
        statements: merged,
        role: role,
        timestamp: timestamp,
        tooling: tooling,
      )
    end

    # Convenience: merge another document into a new document, keeping this
    # one's identity (id, author, role, tooling). The receiver's statements
    # come first so source order reflects "I had these, then I learned
    # those." `last_updated` is bumped to now to signal the change.
    def merge(other : Document) : Document
      Document.merge(
        [self, other],
        id: @id,
        author: @author,
        role: @role,
        timestamp: @timestamp,
        tooling: @tooling,
      ).tap(&.last_updated=(Time.utc))
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
      @version, @tooling, @statements
  end
end
