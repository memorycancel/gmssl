# frozen_string_literal: true

require 'ffi'

module GmSSL
  module Random
    extend FFI::Library
    file = File.join GmSSL.lib, LIB_FILE
    ffi_lib file

    attach_function :rand_bytes, [:pointer, :size_t], :int

    def self.bytes(n = 256)
      buf = FFI::MemoryPointer.new(:uint8, n)
      Random.rand_bytes(buf, n)
      buf.read_bytes(n).unpack('H*').first
    end
  end
end
