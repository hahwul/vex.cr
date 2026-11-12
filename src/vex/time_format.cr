require "json"
require "./error"

module Vex
  module TimeConverter
    extend self

    # Shapes accepted by `STRICT_PARSERS` / `LENIENT_PARSERS`, anchored at both
    # ends. `Time::Format#parse` stops once the pattern is exhausted and leaves
    # the rest of the string unread, so without this gate a value like
    # `"2025-01-01T00:00:00Zjunk"` parsed as a valid instant. Matching first
    # keeps the parsers from accepting a well-formed prefix of garbage.
    # RFC 3339 §5.6 bounds the offset to `time-hour` (00-23) and
    # `time-minute` (00-59); `Time::Format` would otherwise accept `+24:00`
    # and round-trip it as an invalid `date-time`.
    STRICT_SHAPE  = /\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)\z/
    LENIENT_SHAPE = /\A\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?\z/

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
      value = canonicalize(string)

      # A shape-valid string can still carry out-of-range components
      # (`"2025-13-45T99:99:99Z"`). `Time::Format` reports the pattern mismatch
      # as `Time::Format::Error` but lets `Time.local`'s bare `ArgumentError`
      # through, so both are caught and reported as one `ParseError` naming the
      # offending value.
      if STRICT_SHAPE.matches?(value)
        STRICT_PARSERS.each do |fmt|
          return fmt.parse(value)
        rescue Time::Format::Error | ArgumentError
          next
        end
      end

      if LENIENT_SHAPE.matches?(value)
        LENIENT_PARSERS.each do |fmt|
          return fmt.parse(value, location: Time::Location::UTC)
        rescue Time::Format::Error | ArgumentError
          next
        end
      end

      raise ParseError.new("Could not parse VEX timestamp #{string.inspect}")
    end

    # RFC 3339 §5.6 notes that the `T` separator and the `Z` zone designator
    # "may alternatively be lower case". Our format strings spell both in upper
    # case, so fold the lower-case spellings before matching.
    private def canonicalize(string : String) : String
      value = string
      value = value.sub(10, 'T') if value.size > 10 && value[10] == 't'
      value = value.sub(value.size - 1, 'Z') if value.ends_with?('z')
      value
    end

    # Emits `Z` for UTC instants (matching go-vex and the spec example),
    # and the explicit offset like `+09:00` otherwise. Both forms are valid
    # RFC 3339. RFC 3339 offsets have minute resolution, so a time whose
    # offset has a seconds part (a pre-1900 local mean time such as Seoul's
    # +08:27:52, or `Time::Location.fixed(30)`) is emitted in UTC instead:
    # `%:z` would drop the seconds and serialize a different instant.
    def format(time : Time) : String
      time.utc? || time.offset % 60 != 0 ? EMITTER_UTC.format(time.to_utc) : EMITTER.format(time)
    end
  end
end
