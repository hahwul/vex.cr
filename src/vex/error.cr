module Vex
  # Base class for every error this shard raises.
  class Error < Exception
  end

  # Raised when input cannot be decoded into a VEX type: an unknown `status`
  # or `justification` label, a timestamp that isn't RFC 3339, or JSON that
  # doesn't match the document shape. The underlying stdlib exception is kept
  # as the `cause` when there is one.
  class ParseError < Error
  end

  # :nodoc:
  # Spec "OpenVEX documents are serialized in json-ld structs. File encoding
  # MUST be UTF8." Crystal's JSON parser passes invalid bytes through into
  # strings, which then serialize back out as non-UTF-8 output.
  def self.utf8!(input : String | IO) : String
    str = input.is_a?(IO) ? input.gets_to_end : input
    raise ParseError.new("input is not valid UTF-8") unless str.valid_encoding?
    str
  end
end
