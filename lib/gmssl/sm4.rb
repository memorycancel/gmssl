# frozen_string_literal: true

require 'ffi'

require 'gmssl/ghash'

module GmSSL
  module SM4
    extend FFI::Library
    file = File.join GmSSL.lib, LIB_FILE
    ffi_lib file

    SM4_KEY_SIZE = 16
    SM4_BLOCK_SIZE = 16
    SM4_NUM_ROUNDS = 32
    SM4_GCM_MAX_TAG_SIZE = 16

    class SM4_KEY < FFI::Struct
      layout :rk, [:uint32, SM4_NUM_ROUNDS]
    end

    class SM4_CBC_CTX < FFI::Struct
      layout :sm4_key, SM4_KEY,
             :iv, [:uint8, SM4_BLOCK_SIZE],
             :block, [:uint8, SM4_BLOCK_SIZE],
             :block_nbytes, :size_t
    end

    class SM4_CTR_CTX < FFI::Struct
      layout :sm4_key, SM4_KEY,
             :ctr, [:uint8, SM4_BLOCK_SIZE],
             :block, [:uint8, SM4_BLOCK_SIZE],
             :block_nbytes, :size_t
    end

    class SM4_GCM_CTX < FFI::Struct
      layout :enc_ctx, SM4_CTR_CTX,
             :mac_ctx, GmSSL::Ghash::GHASH_CTX, # GHASH_CTX defined in ghash.rb
             :Y, [:uint8, 16],
             :taglen, :size_t,
             :mac, [:uint8, 16],
             :maclen, :size_t,
             :encedlen, :uint64
    end

    attach_function :sm4_set_encrypt_key, [SM4_KEY.by_ref, :pointer], :void
    attach_function :sm4_set_decrypt_key, [SM4_KEY.by_ref, :pointer], :void
    attach_function :sm4_encrypt, [SM4_KEY.by_ref, :pointer, :pointer], :void

    attach_function :sm4_encrypt_blocks, [SM4_KEY.by_ref, :pointer, :size_t, :pointer], :void
    attach_function :sm4_cbc_encrypt_blocks, [SM4_KEY.by_ref, :pointer, :pointer, :size_t, :pointer], :void
    attach_function :sm4_cbc_decrypt_blocks, [SM4_KEY.by_ref, :pointer, :pointer, :size_t, :pointer], :void
    attach_function :sm4_ctr_encrypt_blocks, [SM4_KEY.by_ref, :pointer, :pointer, :size_t, :pointer], :void
    attach_function :sm4_ctr32_encrypt_blocks, [SM4_KEY.by_ref, :pointer, :pointer, :size_t, :pointer], :void

    attach_function :sm4_cbc_padding_encrypt, [SM4_KEY.by_ref, :pointer, :pointer, :size_t, :pointer, :pointer], :int
    attach_function :sm4_cbc_padding_decrypt, [SM4_KEY.by_ref, :pointer, :pointer, :size_t, :pointer, :pointer], :int
    attach_function :sm4_ctr_encrypt, [SM4_KEY.by_ref, :pointer, :pointer, :size_t, :pointer], :void
    attach_function :sm4_ctr32_encrypt, [SM4_KEY.by_ref, :pointer, :pointer, :size_t, :pointer], :void

    attach_function :sm4_cbc_encrypt_init, [SM4_CBC_CTX.by_ref, :pointer, :pointer], :int
    attach_function :sm4_cbc_encrypt_update, [SM4_CBC_CTX.by_ref, :pointer, :size_t, :pointer, :pointer], :int
    attach_function :sm4_cbc_encrypt_finish, [SM4_CBC_CTX.by_ref, :pointer, :pointer], :int
    attach_function :sm4_cbc_decrypt_init, [SM4_CBC_CTX.by_ref, :pointer, :pointer], :int
    attach_function :sm4_cbc_decrypt_update, [SM4_CBC_CTX.by_ref, :pointer, :size_t, :pointer, :pointer], :int
    attach_function :sm4_cbc_decrypt_finish, [SM4_CBC_CTX.by_ref, :pointer, :pointer], :int

    attach_function :sm4_ctr_encrypt_init, [SM4_CTR_CTX.by_ref, :pointer, :pointer], :int
    attach_function :sm4_ctr_encrypt_update, [SM4_CTR_CTX.by_ref, :pointer, :size_t, :pointer, :pointer], :int
    attach_function :sm4_ctr_encrypt_finish, [SM4_CTR_CTX.by_ref, :pointer, :pointer], :int
    attach_function :sm4_ctr32_encrypt_init, [SM4_CTR_CTX.by_ref, :pointer, :pointer], :int
    attach_function :sm4_ctr32_encrypt_update, [SM4_CTR_CTX.by_ref, :pointer, :size_t, :pointer, :pointer], :int
    attach_function :sm4_ctr32_encrypt_finish, [SM4_CTR_CTX.by_ref, :pointer, :pointer], :int

    attach_function :sm4_gcm_encrypt, [SM4_KEY.by_ref, :pointer, :size_t, :pointer, :size_t, :pointer, :size_t, :pointer, :size_t, :pointer], :int
    attach_function :sm4_gcm_decrypt, [SM4_KEY.by_ref, :pointer, :size_t, :pointer, :size_t, :pointer, :size_t, :pointer, :size_t, :pointer], :int

    attach_function :sm4_gcm_encrypt_init, [SM4_GCM_CTX.by_ref, :pointer, :size_t, :pointer, :size_t, :pointer, :size_t, :size_t], :int
    attach_function :sm4_gcm_encrypt_update, [SM4_GCM_CTX.by_ref, :pointer, :size_t, :pointer, :pointer], :int
    attach_function :sm4_gcm_encrypt_finish, [SM4_GCM_CTX.by_ref, :pointer, :pointer], :int
    attach_function :sm4_gcm_decrypt_init, [SM4_GCM_CTX.by_ref, :pointer, :size_t, :pointer, :size_t, :pointer, :size_t, :size_t], :int
    attach_function :sm4_gcm_decrypt_update, [SM4_GCM_CTX.by_ref, :pointer, :size_t, :pointer, :pointer], :int
    attach_function :sm4_gcm_decrypt_finish, [SM4_GCM_CTX.by_ref, :pointer, :pointer], :int

    def self.cbc_encrypt(key, iv, plaintext)
      ctx = SM4::SM4_CBC_CTX.new
      SM4.sm4_cbc_encrypt_init(ctx, key, iv)
      ciphertext = FFI::MemoryPointer.new(:uint8, plaintext.bytesize + SM4::SM4_BLOCK_SIZE)
      outlen = FFI::MemoryPointer.new(:size_t)
      SM4.sm4_cbc_encrypt_update(ctx, plaintext, plaintext.bytesize, ciphertext, outlen)
      ciphertext_len = outlen.read(:size_t)
      SM4.sm4_cbc_encrypt_finish(ctx, ciphertext + ciphertext_len, outlen)
      ciphertext_len += outlen.read(:size_t)
      bytes_to_hex_string ciphertext.read_bytes(ciphertext_len)
    end

    def self.cbc_decrypt(key, iv, ciphertext)
      ciphertext = hex_string_to_packed_bytes ciphertext
      ctx = SM4::SM4_CBC_CTX.new
      SM4.sm4_cbc_decrypt_init(ctx, key, iv)
      decrypted = FFI::MemoryPointer.new(:uint8, ciphertext.bytesize + SM4::SM4_BLOCK_SIZE)
      outlen = FFI::MemoryPointer.new(:size_t)
      SM4.sm4_cbc_decrypt_update(ctx, ciphertext, ciphertext.bytesize, decrypted, outlen)
      decrypted_len = outlen.read(:size_t)
      SM4.sm4_cbc_decrypt_finish(ctx, decrypted + decrypted_len, outlen)
      decrypted_len += outlen.read(:size_t)
      decrypted.read_bytes(decrypted_len)
    end

    def self.ctr_encrypt(input_string, key_hex, ctr_hex)
      key = hex_string_to_packed_bytes(key_hex)
      ctr = hex_string_to_packed_bytes(ctr_hex)
      input_data = input_string.bytes.pack("C*")
      output_data = FFI::MemoryPointer.new(:uint8, input_data.bytesize)
      output_length = FFI::MemoryPointer.new(:size_t)
      key_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_KEY_SIZE)
      ctr_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_BLOCK_SIZE)
      key_ptr.put_array_of_uint8(0, key.bytes)
      ctr_ptr.put_array_of_uint8(0, ctr.bytes)
      ctx = SM4::SM4_CTR_CTX.new
      SM4.sm4_ctr_encrypt_init(ctx, key_ptr, ctr_ptr)
      SM4.sm4_ctr_encrypt_update(ctx, input_data, input_data.bytesize, output_data, output_length)
      SM4.sm4_ctr_encrypt_finish(ctx, output_data, output_length)
      encrypted_data = output_data.read_string(output_length.read(:size_t))
      encrypted_data.unpack("H*")[0]
    end

    def self.gcm_encrypt(key, iv, aad, input)
      key = hex_string_to_packed_bytes key
      iv = hex_string_to_packed_bytes iv
      key_struct = SM4::SM4_KEY.new
      key_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_KEY_SIZE)
      key_ptr.put_array_of_uint8(0, key.bytes)
      SM4::sm4_set_encrypt_key(key_struct, key_ptr)
      iv_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_BLOCK_SIZE)
      iv_ptr.put_array_of_uint8(0, iv.bytes)
      aad_ptr = FFI::MemoryPointer.new(:uint8, aad.bytesize)
      aad_ptr.put_array_of_uint8(0, aad.bytes)
      input_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
      input_ptr.put_array_of_uint8(0, input.bytes)
      output_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
      tag_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_GCM_MAX_TAG_SIZE)
      SM4::sm4_gcm_encrypt(key_struct, iv_ptr, iv.bytesize, aad_ptr, aad.bytesize, input_ptr, input.bytesize, output_ptr, SM4::SM4_GCM_MAX_TAG_SIZE, tag_ptr)
      encrypted_output = encrypted_output = output_ptr.read_string(input.bytesize).unpack1("H*")
      tag = tag_ptr.read_string(SM4::SM4_GCM_MAX_TAG_SIZE).unpack1("H*")
      return encrypted_output, tag
    end

    def self.gcm_decrypt(key, iv, aad, encrypted_output, tag)
      encrypted_output = hex_string_to_packed_bytes encrypted_output
      tag = hex_string_to_packed_bytes tag
      key = hex_string_to_packed_bytes key
      iv = hex_string_to_packed_bytes iv
      key_struct = SM4::SM4_KEY.new
      key_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_KEY_SIZE)
      key_ptr.put_array_of_uint8(0, key.bytes)
      SM4::sm4_set_encrypt_key(key_struct, key_ptr)
      iv_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_BLOCK_SIZE)
      iv_ptr.put_array_of_uint8(0, iv.bytes)
      aad_ptr = FFI::MemoryPointer.new(:uint8, aad.bytesize)
      aad_ptr.put_array_of_uint8(0, aad.bytes)
      encrypted_ptr = FFI::MemoryPointer.new(:uint8, encrypted_output.bytesize)
      encrypted_ptr.put_array_of_uint8(0, encrypted_output.bytes)
      tag_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_GCM_MAX_TAG_SIZE)
      tag_ptr.put_array_of_uint8(0, tag.bytes)
      decrypted_output_ptr = FFI::MemoryPointer.new(:uint8, encrypted_output.bytesize)
      SM4::sm4_gcm_decrypt(key_struct, iv_ptr, iv.bytesize, aad_ptr, aad.bytesize, encrypted_ptr, encrypted_output.bytesize, tag_ptr, SM4::SM4_GCM_MAX_TAG_SIZE, decrypted_output_ptr)
      decrypted_output = decrypted_output_ptr.read_string(encrypted_output.bytesize)
      return decrypted_output
    end
  end
end
