require "json"
require "digest/sha256"
require "./error"
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

    # An empty string is never a valid `@context`, `@id`, or `author`, so — for
    # the same reason `version: 0` is never emitted (see below) — the sentinel
    # is not serialized. Emitting `"@id": ""` would assert an empty IRI that the
    # spec (and our own `validate`) rejects, and would add a key that wasn't in
    # the parsed input. The gap is still surfaced through `validate`.

    @[JSON::Field(key: "@context", ignore_serialize: context.empty?)]
    property context : String = ""

    @[JSON::Field(key: "@id", ignore_serialize: id.empty?)]
    property id : String = ""

    @[JSON::Field(ignore_serialize: author.empty?)]
    property author : String = ""

    @[JSON::Field(ignore_serialize: role.nil?)]
    property role : String?

    @[JSON::Field(converter: Vex::TimeConverter, ignore_serialize: timestamp.nil?)]
    property timestamp : Time?

    @[JSON::Field(key: "last_updated", converter: Vex::TimeConverter, ignore_serialize: last_updated.nil?)]
    property last_updated : Time?

    # `version` defaults to 0 as an "unset" sentinel so we can permissively
    # parse documents that omit it. The spec requires `version >= 1`, so a
    # sentinel 0 is never serialized — emitting `"version": 0` would produce
    # output the spec (and our own `validate`) rejects. The gap is still
    # surfaced through `validate`.
    @[JSON::Field(ignore_serialize: version < 1)]
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
      # Spec Definitions: a document "groups together one or more VEX
      # statements" (schema: `statements` has `minItems: 1`).
      errors << "statements must contain at least one statement" if statements.empty?

      # Spec: statement @id "must be unique for each statement in the document".
      seen_ids = Set(String).new
      # Schema: `statements` is `uniqueItems`.
      first_index = {} of Statement => Int32
      statements.each_with_index do |stmt, i|
        if (j = first_index.put_if_absent(stmt, i)) != i
          errors << "statements[#{i}]: duplicate of statements[#{j}]"
        elsif sid = stmt.id
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
    #
    # Matching follows go-vex `Statement.Matches`: *product* must match a
    # statement product (`Component#matches?`, purl-aware). With
    # *subcomponents* given, a product that lists subcomponents must also
    # list one of them; a product without subcomponents matches regardless.
    def find_statements(product : String, vulnerability : String, subcomponents : Array(String) = [] of String) : Array(Statement)
      subs = subcomponents.empty? ? [""] : subcomponents
      statements.select do |s|
        next false unless s.vulnerability.try &.matches?(vulnerability)
        s.products.try(&.any? { |p| subs.any? { |sc| p.matches?(product, sc) } }) || false
      end
    end

    # Returns the most recent statement for the given product/vuln identifier
    # pair. Compares timestamps with the document timestamp as fallback. Ties
    # resolve to the last statement in source order — matching go-vex, which
    # stable-sorts ascending then iterates from the end. This honors the
    # conceptual model that newer statements (those appended later) override
    # older ones when their timestamps cannot.
    def effective_statement(product : String, vulnerability : String, subcomponents : Array(String) = [] of String) : Statement?
      matching = find_statements(product, vulnerability, subcomponents)
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

    # go-vex `CanonicalHash`: a SHA-256 over the document timestamp, version,
    # and author, then every statement (sorted by vulnerability name, then
    # effective timestamp) contributing its vulnerability @id, name, sorted
    # aliases, status, justification, effective timestamp, and sorted product
    # strings (each product's and direct subcomponents' @id, hashes, and
    # identifiers). Timestamps are Unix seconds. `last_updated`, notes,
    # impact/action statements, and role/tooling don't affect it.
    #
    # The input is byte-for-byte go-vex's so both libraries mint the same
    # `@id` for the same document. That format joins raw values with `:`
    # and so is not injective (values containing `:` can collide); it is
    # kept for interop. Subcomponents nested deeper than one level, which
    # go-vex doesn't model, are not part of the hash.
    #
    # Raises `Vex::Error` when the document has no `timestamp`.
    def canonical_hash : String
      doc_ts = @timestamp || raise Error.new("document timestamp is required to compute canonical hash")
      doc_unix = doc_ts.to_unix
      # Stable sort like go-vex's `SortStatements` (index breaks ties).
      # ponytail: go-vex also treats a zero time (0001-01-01) as unset when
      # sorting; not mirrored.
      sorted = @statements.each_with_index.to_a.sort_by! do |(st, i)|
        {st.vulnerability.try(&.name) || "", st.timestamp || doc_ts, i}
      end
      cs = String.build do |io|
        io << doc_unix << ':' << @version << ':' << @author
        sorted.each do |(st, _)|
          vuln = st.vulnerability
          io << ':' << vuln.try(&.id) << ':' << vuln.try(&.name) << ':'
          vuln.try(&.aliases).try &.sort.join(io, ':')
          io << ':' << st.status.wire_value << ':' << st.justification.try(&.wire_value)
          io << ':' << (st.timestamp.try(&.to_unix) || doc_unix)
          prods = st.products.try &.map do |product|
            String.build do |pio|
              Document.write_component_cstring(pio, product)
              product.subcomponents.try &.each { |sub| Document.write_component_cstring(pio, sub) }
            end
          end
          prods.try &.sort!.join(io, ':')
        end
      end
      Digest::SHA256.hexdigest(cs)
    end

    # Recomputes and sets `@id` from `canonical_hash`, in go-vex's
    # `{PUBLIC_NAMESPACE}/public/vex-<sha256>` shape. Spec "Public IRI
    # Namespaces": `public` is the reserved name "where anybody that needs a
    # valid IRI can issue identifiers". The new value is returned for
    # chaining. Raises `Vex::Error` when the document has no `timestamp`.
    def regenerate_id : String
      @id = "#{PUBLIC_NAMESPACE}/public/vex-#{canonical_hash}"
    end

    # go-vex `writeComponentCString`.
    protected def self.write_component_cstring(io : IO, component : Component) : Nil
      io << ':' << component.id
      component.hashes.try &.to_a.sort_by!(&.first).each { |(k, v)| io << ':' << k << '@' << v }
      component.identifiers.try &.to_a.sort_by!(&.first).each { |(k, v)| io << ':' << k << '@' << v }
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
    # an `@id` is generated with `regenerate_id`, which needs `timestamp:`
    # (raises `Vex::Error` when it is nil).
    #
    # Raises `Vex::Error` when a statement has no timestamp, neither does its
    # source document, and the result would have one: the statement would be
    # re-dated to the merged document's timestamp.
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
      docs.each_with_index do |doc, di|
        doc.statements.each_with_index do |stmt, si|
          next unless seen.add?(stmt)
          # Spec "Updating Statements with Inherited Data": the integrity of
          # untouched statements MUST be preserved, so a statement inheriting
          # its source document's timestamp keeps it explicitly rather than
          # silently adopting the merged document's (go-vex does the same).
          # Dedup runs first so the first occurrence's timestamp is kept.
          if stmt.timestamp.nil? && (ts = doc.timestamp)
            stmt = stmt.dup
            stmt.timestamp = ts
            # The filled-in copy can equal a statement that carried the same
            # timestamp explicitly; keeping both would violate the schema's
            # `uniqueItems` on `statements`.
            next unless seen.add?(stmt)
          elsif stmt.timestamp.nil? && timestamp
            # Nothing to inherit: the statement would silently take the merged
            # document's timestamp and outrank genuinely newer statements.
            # go-vex refuses the same case. With `timestamp: nil` (e.g. an
            # envelope supplies the time) nothing is re-dated, so it's allowed.
            raise Error.new("docs[#{di}].statements[#{si}] has no timestamp to inherit (its document has none)")
          end
          merged << stmt
        end
      end
      Document.new(
        id: id,
        author: author,
        statements: merged,
        role: role,
        timestamp: timestamp,
        tooling: tooling,
      ).tap { |doc| doc.regenerate_id if id.empty? }
    end

    # Convenience: merge another document into a new document, keeping this
    # one's identity (id, author, role, tooling). The receiver's statements
    # come first so source order reflects "I had these, then I learned
    # those." `last_updated` is bumped to now and `version` incremented, since
    # the spec says the version "must be incremented when any content within
    # the VEX document changes".
    def merge(other : Document) : Document
      raise Error.new("version #{@version} cannot be incremented") if @version == Int32::MAX
      Document.merge(
        [self, other],
        id: @id,
        author: @author,
        role: @role,
        timestamp: @timestamp,
        tooling: @tooling,
      ).tap do |doc|
        doc.last_updated = Time.utc
        doc.version = @version + 1
        # The canonical hash covers the version, so re-mint after the bump.
        doc.regenerate_id if @id.empty?
      end
    end

    def to_json_pretty : String
      String.build do |io|
        JSON.build(io, indent: "  ") { |j| to_json(j) }
      end
    end

    # Parses a VEX document. Malformed JSON and shape mismatches surface as
    # `Vex::ParseError` (with the stdlib exception kept as `cause`) so callers
    # have one error type to rescue, alongside the `Vex::ParseError` already
    # raised for unknown status/justification labels and bad timestamps.
    def self.from_json(string_or_io) : self
      super(Vex.utf8!(string_or_io))
    rescue ex : JSON::ParseException
      raise ParseError.new(ex.message, cause: ex)
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
