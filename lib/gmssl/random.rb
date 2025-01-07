# frozen_string_literal: true

require 'ffi'

module GmSSL
  module Random
    extend FFI::Library
    file = File.join GmSSL.lib, LIB_FILE
    ffi_lib file

    attach_function :rand_bytes, [:pointer, :size_t], :int
  end
end
