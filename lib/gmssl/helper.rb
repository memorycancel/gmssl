# frozen_string_literal: true

module Helper
  # Example usage
  # hex_string = "54A38E3B599E48C4F581FEC14B62EA29"
  # packed_bytes = hex_string_to_packed_bytes(hex_string)
  # puts packed_bytes
  def hex_string_to_packed_bytes(hex_string)
    hex_string.scan(/../).map { |byte| byte.hex }.pack("C*")
  end

  # Example usage
  # bytes = [0x54, 0xA3, 0x8E, 0x3B, 0x59, 0x9E, 0x48, 0xC4]
  # hex_string = bytes_to_hex_string(bytes.pack('C*'))
  # puts hex_string
  def bytes_to_hex_string(bytes)
    bytes.unpack1('H*')
  end
end
