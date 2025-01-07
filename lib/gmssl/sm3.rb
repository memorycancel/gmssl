# frozen_string_literal: true

require 'ffi'

module GmSSL
  module SM3
    extend FFI::Library
    file = File.join GmSSL.lib, LIB_FILE
    ffi_lib file

    SM3_DIGEST_SIZE = 32
    SM3_BLOCK_SIZE = 64
    SM3_STATE_WORDS = 8

    # Define the SM3_CTX structure
    class SM3_CTX < FFI::Struct
      layout :digest, [:uint32, SM3_STATE_WORDS],
             :nblocks, :uint64,
             :block, [:uint8, SM3_BLOCK_SIZE],
             :num, :size_t
    end

    # Define the SM3_HMAC_CTX structure
    class SM3_HMAC_CTX < FFI::Struct
      layout :sm3_ctx, SM3_CTX,
             :key, [:uint8, SM3_BLOCK_SIZE]
    end

    # Define the SM3_KDF_CTX structure
    class SM3_KDF_CTX < FFI::Struct
      layout :sm3_ctx, SM3_CTX,
             :outlen, :size_t
    end

    # Define the SM3_DIGEST_CTX structure
    class SM3_DIGEST_CTX < FFI::Union
      layout :sm3_ctx, SM3_CTX,
             :hmac_ctx, SM3_HMAC_CTX,
             :state, :int
    end

    # Attach functions
    attach_function :sm3_compress_blocks, [:pointer, :pointer, :size_t], :void
    attach_function :sm3_init, [SM3_CTX.by_ref], :void
    attach_function :sm3_update, [SM3_CTX.by_ref, :pointer, :size_t], :void
    attach_function :sm3_finish, [SM3_CTX.by_ref, :pointer], :void

    attach_function :sm3_hmac_init, [SM3_HMAC_CTX.by_ref, :pointer, :size_t], :void
    attach_function :sm3_hmac_update, [SM3_HMAC_CTX.by_ref, :pointer, :size_t], :void
    attach_function :sm3_hmac_finish, [SM3_HMAC_CTX.by_ref, :pointer], :void

    attach_function :sm3_kdf_init, [SM3_KDF_CTX.by_ref, :size_t], :void
    attach_function :sm3_kdf_update, [SM3_KDF_CTX.by_ref, :pointer, :size_t], :void
    attach_function :sm3_kdf_finish, [SM3_KDF_CTX.by_ref, :pointer], :void

    attach_function :sm3_pbkdf2, [:string, :size_t, :pointer, :size_t, :size_t, :size_t, :pointer], :int

    attach_function :sm3_digest_init, [SM3_DIGEST_CTX.by_ref, :pointer, :size_t], :int
    attach_function :sm3_digest_update, [SM3_DIGEST_CTX.by_ref, :pointer, :size_t], :int
    attach_function :sm3_digest_finish, [SM3_DIGEST_CTX.by_ref, :pointer], :int
  end
end
