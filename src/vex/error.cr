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
end
