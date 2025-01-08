# frozen_string_literal: true

require 'ffi'

module GmSSL
  module Ghash
    extend FFI::Library
    file = File.join GmSSL.lib, LIB_FILE
    ffi_lib file

    class GF128 < FFI::Struct
      layout :data, [:uint64, 2]
    end

    class GHASH_CTX < FFI::Struct
      layout :H, GF128,
             :X, GF128,
             :aadlen, :size_t,
             :clen, :size_t,
             :block, [:uint8, 16],
             :num, :size_t
    end

    attach_function :ghash, [:pointer, :pointer, :size_t, :pointer, :size_t, :pointer], :void
    attach_function :ghash_init, [GHASH_CTX.by_ref, :pointer, :pointer, :size_t], :void
    attach_function :ghash_update, [GHASH_CTX.by_ref, :pointer, :size_t], :void
    attach_function :ghash_finish, [GHASH_CTX.by_ref, :pointer], :void
  end
end
