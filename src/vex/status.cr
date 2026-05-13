require "json"

module Vex
  enum Status
    NotAffected
    Affected
    Fixed
    UnderInvestigation

    def to_s(io : IO) : Nil
      io << wire_value
    end

    # Crystal's default enum `to_s` returns the member name (e.g. `"Fixed"`).
    # We want the wire value everywhere — `puts stmt.status`, string
    # interpolation, log lines — so override the no-arg overload too.
    def to_s : String
      wire_value
    end

    def wire_value : String
      case self
      in NotAffected        then "not_affected"
      in Affected           then "affected"
      in Fixed              then "fixed"
      in UnderInvestigation then "under_investigation"
      end
    end

    def self.parse_wire(value : String) : Status
      case value
      when "not_affected"        then NotAffected
      when "affected"            then Affected
      when "fixed"               then Fixed
      when "under_investigation" then UnderInvestigation
      else
        raise ArgumentError.new("invalid VEX status #{value.inspect}")
      end
    end

    def self.new(parser : JSON::PullParser) : Status
      parse_wire(parser.read_string)
    end

    def to_json(json : JSON::Builder) : Nil
      json.string(wire_value)
    end
  end
end
