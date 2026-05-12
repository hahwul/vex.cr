require "json"

module Vex
  module TimeConverter
    extend self

    PARSERS = [
      Time::Format.new("%FT%T.%N%:z"),
      Time::Format.new("%FT%T%:z"),
      Time::Format.new("%FT%T.%NZ"),
      Time::Format.new("%FT%TZ"),
    ]

    EMITTER = Time::Format.new("%FT%T.%N%:z")

    def from_json(parser : JSON::PullParser) : Time
      parse(parser.read_string)
    end

    def to_json(value : Time, json : JSON::Builder) : Nil
      json.string(EMITTER.format(value))
    end

    def parse(string : String) : Time
      PARSERS.each do |fmt|
        begin
          return fmt.parse(string)
        rescue Time::Format::Error
          next
        end
      end
      raise Time::Format::Error.new("Could not parse VEX timestamp #{string.inspect}")
    end

    def format(time : Time) : String
      EMITTER.format(time)
    end
  end
end
