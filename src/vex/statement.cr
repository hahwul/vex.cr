require "json"
require "./status"
require "./justification"
require "./vulnerability"
require "./component"
require "./time_format"

module Vex
  class Statement
    include JSON::Serializable

    @[JSON::Field(key: "@id", ignore_serialize: id.nil?)]
    property id : String?

    @[JSON::Field(ignore_serialize: version.nil?)]
    property version : Int32?

    @[JSON::Field(ignore_serialize: vulnerability.nil?)]
    property vulnerability : Vulnerability?

    @[JSON::Field(converter: Vex::TimeConverter, ignore_serialize: timestamp.nil?)]
    property timestamp : Time?

    @[JSON::Field(key: "last_updated", converter: Vex::TimeConverter, ignore_serialize: last_updated.nil?)]
    property last_updated : Time?

    @[JSON::Field(ignore_serialize: products.nil?)]
    property products : Array(Product)?

    property status : Status

    @[JSON::Field(key: "status_notes", ignore_serialize: status_notes.nil?)]
    property status_notes : String?

    @[JSON::Field(ignore_serialize: justification.nil?)]
    property justification : Justification?

    @[JSON::Field(key: "impact_statement", ignore_serialize: impact_statement.nil?)]
    property impact_statement : String?

    @[JSON::Field(key: "action_statement", ignore_serialize: action_statement.nil?)]
    property action_statement : String?

    @[JSON::Field(
      key: "action_statement_timestamp",
      converter: Vex::TimeConverter,
      ignore_serialize: action_statement_timestamp.nil?,
    )]
    property action_statement_timestamp : Time?

    @[JSON::Field(ignore_serialize: supplier.nil?)]
    property supplier : String?

    def initialize(
      @status : Status,
      @vulnerability : Vulnerability? = nil,
      @products : Array(Product)? = nil,
      @id : String? = nil,
      @version : Int32? = nil,
      @timestamp : Time? = nil,
      @last_updated : Time? = nil,
      @status_notes : String? = nil,
      @justification : Justification? = nil,
      @impact_statement : String? = nil,
      @action_statement : String? = nil,
      @action_statement_timestamp : Time? = nil,
      @supplier : String? = nil,
    )
    end

    # Returns an array of validation errors. Empty array means the statement
    # is valid per the OpenVEX spec's conditional-field rules.
    def validate : Array(String)
      errors = [] of String

      # Spec: `vulnerability` is a required field, and within it `name` is
      # required.
      if (vuln = vulnerability).nil?
        errors << "vulnerability is required"
      else
        vuln.validate.each { |e| errors << "vulnerability: #{e}" }
      end

      # Spec: "Product details MUST include [product_id]" — each product must
      # be identifiable by @id, an entry in `identifiers`, or `hashes`.
      # Subcomponents inherit the same requirement from the Component fields
      # table; an unidentifiable subcomponent conveys no actionable info.
      products.try &.each_with_index do |product, pi|
        errors << "products[#{pi}] has no @id, identifiers, or hashes" unless product.identified?
        # Subcomponents may nest (spec lists `subcomponents` on Component) —
        # walk the tree so an unidentifiable component at any depth is flagged.
        walk_subcomponents(product, "products[#{pi}]") do |sub, path|
          errors << "#{path} has no @id, identifiers, or hashes" unless sub.identified?
        end
      end

      case status
      when Status::NotAffected
        if justification.nil? && (impact_statement.nil? || impact_statement.try(&.empty?))
          errors << "status 'not_affected' requires justification or impact_statement"
        end
        unless action_statement.nil?
          errors << "action_statement must not be set when status is 'not_affected'"
        end
      when Status::Affected
        if action_statement.nil? || action_statement.try(&.empty?)
          errors << "status 'affected' requires action_statement"
        end
        unless justification.nil?
          errors << "justification must not be set when status is 'affected'"
        end
        unless impact_statement.nil?
          errors << "impact_statement must not be set when status is 'affected'"
        end
      when Status::Fixed, Status::UnderInvestigation
        # Spec: justification and impact_statement only carry meaning under
        # `not_affected` ("why not affected"). Their presence on `fixed` or
        # `under_investigation` is a producer mistake.
        unless justification.nil?
          errors << "justification must not be set when status is '#{status}'"
        end
        unless impact_statement.nil?
          errors << "impact_statement must not be set when status is '#{status}'"
        end
      end

      # An action_statement_timestamp without an action_statement is
      # meaningless — there's nothing for the timestamp to qualify.
      if action_statement_timestamp && (action_statement.nil? || action_statement.try(&.empty?))
        errors << "action_statement_timestamp must not be set without action_statement"
      end

      errors
    end

    def valid? : Bool
      validate.empty?
    end

    # Pre-order walk of a component's subcomponent tree, yielding each
    # descendant with its bracketed path prefix (e.g.
    # `products[0].subcomponents[1].subcomponents[0]`).
    protected def walk_subcomponents(component : Component, prefix : String, &block : Subcomponent, String ->) : Nil
      component.subcomponents.try &.each_with_index do |sub, i|
        path = "#{prefix}.subcomponents[#{i}]"
        block.call(sub, path)
        walk_subcomponents(sub, path, &block)
      end
    end

    def_equals_and_hash @id, @version, @vulnerability, @timestamp, @last_updated,
      @products, @status, @status_notes, @justification, @impact_statement,
      @action_statement, @action_statement_timestamp, @supplier
  end
end
