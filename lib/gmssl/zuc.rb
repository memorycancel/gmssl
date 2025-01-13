# frozen_string_literal: true

require 'ffi'

module GmSSL
  module ZUC
    extend FFI::Library
    file = File.join GmSSL.lib, LIB_FILE
    ffi_lib file

    ZUC_KEY_SIZE = 16
    ZUC_IV_SIZE = 16

    class ZUC_STATE < FFI::Struct
      layout :LFSR, [:uint32, 16],
             :R1, :uint32,
             :R2, :uint32
    end

    class ZUC_CTX < FFI::Struct
      layout :zuc_state, ZUC_STATE,
             :block, [:uint8, 4],
             :block_nbytes, :size_t
    end

    attach_function :zuc_init, [ZUC_STATE.by_ref, :pointer, :pointer], :void
    attach_function :zuc_encrypt, [ZUC_STATE.by_ref, :pointer, :size_t, :pointer], :void
    attach_function :zuc_encrypt_init, [ZUC_CTX.by_ref, :pointer, :pointer], :int
    attach_function :zuc_encrypt_update, [ZUC_CTX.by_ref, :pointer, :size_t, :pointer, :pointer], :int
    attach_function :zuc_encrypt_finish, [ZUC_CTX.by_ref, :pointer, :pointer], :int
  end
end
