require "json"
require "./error"

module Vex
  enum Justification
    ComponentNotPresent
    VulnerableCodeNotPresent
    VulnerableCodeNotInExecutePath
    VulnerableCodeCannotBeControlledByAdversary
    InlineMitigationsAlreadyExist

    def to_s(io : IO) : Nil
      io << wire_value
    end

    # See `Vex::Status#to_s` for the rationale: default enum `to_s` returns
    # the member name; we want the wire value in all string contexts.
    def to_s : String
      wire_value
    end

    def wire_value : String
      case self
      in ComponentNotPresent                         then "component_not_present"
      in VulnerableCodeNotPresent                    then "vulnerable_code_not_present"
      in VulnerableCodeNotInExecutePath              then "vulnerable_code_not_in_execute_path"
      in VulnerableCodeCannotBeControlledByAdversary then "vulnerable_code_cannot_be_controlled_by_adversary"
      in InlineMitigationsAlreadyExist               then "inline_mitigations_already_exist"
      end
    end

    def self.parse_wire(value : String) : Justification
      case value
      when "component_not_present"                             then ComponentNotPresent
      when "vulnerable_code_not_present"                       then VulnerableCodeNotPresent
      when "vulnerable_code_not_in_execute_path"               then VulnerableCodeNotInExecutePath
      when "vulnerable_code_cannot_be_controlled_by_adversary" then VulnerableCodeCannotBeControlledByAdversary
      when "inline_mitigations_already_exist"                  then InlineMitigationsAlreadyExist
      else
        raise ParseError.new("invalid VEX justification #{value.inspect}")
      end
    end

    def self.new(parser : JSON::PullParser) : Justification
      parse_wire(parser.read_string)
    end

    def to_json(json : JSON::Builder) : Nil
      json.string(wire_value)
    end
  end
end
