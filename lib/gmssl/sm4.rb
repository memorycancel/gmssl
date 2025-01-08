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

  end
end
