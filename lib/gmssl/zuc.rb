# frozen_string_literal: true

require 'ffi'
require 'helper'

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

    def self.encrypt(key, iv, input)
      key = hex_string_to_packed_bytes key
      iv = hex_string_to_packed_bytes iv
      key_ptr = FFI::MemoryPointer.new(:uint8, ZUC::ZUC_KEY_SIZE)
      key_ptr.put_array_of_uint8(0, key.bytes)
      iv_ptr = FFI::MemoryPointer.new(:uint8, ZUC::ZUC_IV_SIZE)
      iv_ptr.put_array_of_uint8(0, iv.bytes)
      ctx = ZUC::ZUC_CTX.new
      ZUC::zuc_encrypt_init(ctx, key_ptr, iv_ptr)
      input_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
      input_ptr.put_array_of_uint8(0, input.bytes)
      output_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
      outlen_ptr = FFI::MemoryPointer.new(:size_t)
      ZUC::zuc_encrypt_update(ctx, input_ptr, input.bytesize, output_ptr, outlen_ptr)
      ZUC::zuc_encrypt_finish(ctx, output_ptr, outlen_ptr)
      encrypted_output = output_ptr.get_array_of_uint8(0, input.bytesize)
      bytes_to_hex_string encrypted_output.pack('C*')
    end

    def self.decrypt(key, iv, encrypted_output)
      encrypted_output = hex_string_to_packed_bytes encrypted_output
      key = hex_string_to_packed_bytes key
      iv = hex_string_to_packed_bytes iv
      key_ptr = FFI::MemoryPointer.new(:uint8, ZUC::ZUC_KEY_SIZE)
      key_ptr.put_array_of_uint8(0, key.bytes)
      iv_ptr = FFI::MemoryPointer.new(:uint8, ZUC::ZUC_IV_SIZE)
      iv_ptr.put_array_of_uint8(0, iv.bytes)
      ctx = ZUC::ZUC_CTX.new
      ZUC::zuc_encrypt_init(ctx, key_ptr, iv_ptr)
      encrypted_input_ptr = FFI::MemoryPointer.new(:uint8, encrypted_output.bytesize)
      encrypted_input_ptr.put_array_of_uint8(0, encrypted_output.bytes)
      decrypted_output_ptr = FFI::MemoryPointer.new(:uint8, encrypted_output.bytesize)
      outlen_ptr = FFI::MemoryPointer.new(:size_t)
      ZUC::zuc_encrypt_update(ctx, encrypted_input_ptr, encrypted_output.bytesize, decrypted_output_ptr, outlen_ptr)
      ZUC::zuc_encrypt_finish(ctx, decrypted_output_ptr, outlen_ptr)
      decrypted_output = decrypted_output_ptr.get_array_of_uint8(0, encrypted_output.bytesize)
      decrypted_output.pack('C*')
    end
  end
end
