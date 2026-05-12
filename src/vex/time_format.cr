require "json"

module Vex
  module TimeConverter
    extend self

    # RFC 3339 variants the spec mandates. These run first.
    STRICT_PARSERS = [
      Time::Format.new("%FT%T.%N%:z"),
      Time::Format.new("%FT%T%:z"),
      Time::Format.new("%FT%T.%NZ"),
      Time::Format.new("%FT%TZ"),
    ]

    # Lenient fallbacks accommodate real-world emitters that drop the
    # timezone or use a space separator. Canonical's Ubuntu Security Notice
    # docs are one such producer (`"2025-07-08 22:59:24.546301"`). When the
    # input has no zone we assume UTC, which matches the most common
    # producer intent and lets these docs interoperate.
    LENIENT_PARSERS = [
      Time::Format.new("%FT%T.%N"),
      Time::Format.new("%FT%T"),
      Time::Format.new("%F %T.%N"),
      Time::Format.new("%F %T"),
    ]

    EMITTER     = Time::Format.new("%FT%T.%N%:z")
    EMITTER_UTC = Time::Format.new("%FT%T.%NZ")

    def from_json(parser : JSON::PullParser) : Time
      parse(parser.read_string)
    end

    def to_json(value : Time, json : JSON::Builder) : Nil
      json.string(format(value))
    end

    def parse(string : String) : Time
      STRICT_PARSERS.each do |fmt|
        begin
          return fmt.parse(string)
        rescue Time::Format::Error
          next
        end
      end
      LENIENT_PARSERS.each do |fmt|
        begin
          return fmt.parse(string, location: Time::Location::UTC)
        rescue Time::Format::Error
          next
        end
      end
      raise Time::Format::Error.new("Could not parse VEX timestamp #{string.inspect}")
    end

    # Emits `Z` for UTC instants (matching go-vex and the spec example),
    # and the explicit offset like `+09:00` otherwise. Both forms are valid
    # RFC 3339.
    def format(time : Time) : String
      (time.utc? ? EMITTER_UTC : EMITTER).format(time)
    end
  end
end
