# frozen_string_literal: true

# Example usage
# hex_string = "54A38E3B599E48C4F581FEC14B62EA29"
# packed_bytes = hex_string_to_packed_bytes(hex_string)
# puts packed_bytes
def hex_string_to_packed_bytes(hex_string)
  hex_string.scan(/../).map { |byte| byte.hex }.pack("C*")
end
