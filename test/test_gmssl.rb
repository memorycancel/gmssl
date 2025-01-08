# frozen_string_literal: true

require "minitest/autorun"
require "gmssl"
require "helper"

class GmsslTest < Minitest::Test
  include GmSSL

  #  1. 测试c库路径
  def test_root
    assert_includes __FILE__, GmSSL.root
  end

  #  2. 测试版本
  def test_version_num
    assert_equal Version.gmssl_version_num, 30102
  end

  def test_version_str
    assert_equal Version.gmssl_version_str, 'GmSSL 3.1.2 Dev'
  end

  # 3. 测试随机生成器
  def test_rand_bytes
    buf = FFI::MemoryPointer.new(:uint8, 256)
    result = Random.rand_bytes(buf, 256)
    assert_equal result, 1
    assert_equal buf.read_bytes(256).unpack('H*').first.length, 512
  end

  # 4   测试SM3
  # 4.1 测试SM3哈希
  def test_sm3
    # echo -n abc | `pwd`/GmSSL/build/bin/gmssl sm3
    # 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
    sm3_bin_str =
      "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

    # Initialize SM3
    sm3_ctx = SM3::SM3_CTX.new
    SM3.sm3_init(sm3_ctx)

    # Update SM3 context with data
    data = "abc"
    SM3.sm3_update(sm3_ctx, data, data.bytesize)

    # Finalize the hash
    digest = FFI::MemoryPointer.new(:uint8, SM3::SM3_DIGEST_SIZE)
    SM3.sm3_finish(sm3_ctx, digest)
    sm3_digest_str = digest.read_bytes(SM3::SM3_DIGEST_SIZE).unpack1('H*')
    assert_equal sm3_digest_str, sm3_bin_str
  end

  # 4.2 测试HMAC-SM3消息认证码
  def test_sm3_hmac
    # KEY_HEX=`$PWD/GmSSL/build/bin/gmssl rand -outlen 16 -hex`
    # 54A38E3B599E48C4F581FEC14B62EA29
    # echo -n abc | `pwd`/GmSSL/build/bin/gmssl sm3hmac -key $KEY_HEX
    # 130eb2c6bc1e22cb1d7177089c59527e09aaa96a08fbaccf05c86dac034615b8

    # key = [
    #   0x54, 0xA3, 0x8E, 0x3B, 0x59, 0x9E, 0x48, 0xC4,
    #   0xF5, 0x81, 0xFE, 0xC1, 0x4B, 0x62, 0xEA, 0x29
    # ].pack("C*")
    key = hex_string_to_packed_bytes("54A38E3B599E48C4F581FEC14B62EA29")
    data = "abc"

    ctx = SM3::SM3_HMAC_CTX.new
    SM3.sm3_hmac_init(ctx, key, key.bytesize)
    SM3.sm3_hmac_update(ctx, data, data.bytesize)
    mac = FFI::MemoryPointer.new(:uint8, SM3::SM3_HMAC_SIZE)
    SM3.sm3_hmac_finish(ctx, mac)
    res = mac.read_string(SM3::SM3_HMAC_SIZE).unpack1('H*')
    assert_equal res, "130eb2c6bc1e22cb1d7177089c59527e09aaa96a08fbaccf05c86dac034615b8"
  end

  # 4.3 测试基于SM3的口令的密钥导出函数 PBKDF2
  def test_sm3_pbkdf2
    # `pwd`/GmSSL/build/bin/gmssl rand -outlen 8 -hex
    # 667D1BD0262E24E8
    # `pwd`/GmSSL/build/bin/gmssl sm3_pbkdf2 -pass P@ssw0rd -salt 667D1BD0262E24E8 -iter 10000 -outlen 16 -hex
    # dd4fd234a828135264c7c89c13b7e1b3

    password = "P@ssw0rd"
    # salt = [0x66, 0x7D, 0x1B, 0xD0, 0x26, 0x2E, 0x24, 0xE8].pack("C*") # salt
    salt = hex_string_to_packed_bytes("667D1BD0262E24E8")
    iterations = SM3::SM3_PBKDF2_MIN_ITER # 10000
    outlen = 16 # Desired length of the output key
    out = FFI::MemoryPointer.new(:uint8, outlen)
    res = SM3.sm3_pbkdf2(password, password.bytesize, salt, salt.bytesize, iterations, outlen, out)
    out_key_str = out.read_string(outlen).unpack1('H*')
    assert_equal res, 1
    assert_equal out_key_str, "dd4fd234a828135264c7c89c13b7e1b3"
  end

  # 5   测试SM4
  # 5.1 测试SM4-CBC加密模式
  def test_sm4_cbc
    # `pwd`/GmSSL/build/bin/gmssl rand -outlen 20 -hex # TEXT: hello
    # `pwd`/GmSSL/build/bin/gmssl rand -outlen 16 -hex # KEY: 117B5119CDFDD46288DAF9064414D801
    # `pwd`/GmSSL/build/bin/gmssl rand -outlen 16 -hex # IV: 5428F71057DD4AD68C34E38BEA700309
    # echo -n hello | \
    #     `pwd`/GmSSL/build/bin/gmssl sm4_cbc -encrypt \
    #         -key 117B5119CDFDD46288DAF9064414D801 \
    #         -iv 5428F71057DD4AD68C34E38BEA700309 \
    #         -out sm4_cbc_ciphertext.bin

    # `pwd`/GmSSL/build/bin/gmssl sm4_cbc -decrypt \
    #      -key 117B5119CDFDD46288DAF9064414D801 \
    #      -iv 5428F71057DD4AD68C34E38BEA700309 \
    #      -in sm4_cbc_ciphertext.bin
    # hello

    def sm4_cbc_encrypt_decrypt(key, iv, plaintext)
      ctx = SM4::SM4_CBC_CTX.new

      # Encrypt
      SM4.sm4_cbc_encrypt_init(ctx, key, iv)
      ciphertext = FFI::MemoryPointer.new(:uint8, plaintext.bytesize + SM4::SM4_BLOCK_SIZE)
      outlen = FFI::MemoryPointer.new(:size_t)
      SM4.sm4_cbc_encrypt_update(ctx, plaintext, plaintext.bytesize, ciphertext, outlen)
      ciphertext_len = outlen.read(:size_t)
      SM4.sm4_cbc_encrypt_finish(ctx, ciphertext + ciphertext_len, outlen)
      ciphertext_len += outlen.read(:size_t)

      # Decrypt
      SM4.sm4_cbc_decrypt_init(ctx, key, iv)
      decrypted = FFI::MemoryPointer.new(:uint8, ciphertext_len + SM4::SM4_BLOCK_SIZE)
      outlen = FFI::MemoryPointer.new(:size_t)
      SM4.sm4_cbc_decrypt_update(ctx, ciphertext, ciphertext_len, decrypted, outlen)
      decrypted_len = outlen.read(:size_t)
      SM4.sm4_cbc_decrypt_finish(ctx, decrypted + decrypted_len, outlen)
      decrypted_len += outlen.read(:size_t)

      decrypted.read_bytes(decrypted_len)
    end

    key = "117B5119CDFDD46288DAF9064414D801"  # 16 bytes key
    iv = "5428F71057DD4AD68C34E38BEA700309"   # 16 bytes IV
    plaintext = "Hello, sm4_cbc!"

    decrypted_text = sm4_cbc_encrypt_decrypt(key, iv, plaintext)
    assert_equal decrypted_text, plaintext
  end

  # 5.2 测试SM4-CTR加密模式
  def test_sm4_ctr
    def encrypt_string(input_string, key_hex, ctr_hex)
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
      encrypted_data.unpack("H*")[0] # Return hex string representation of encrypted data
    end

    key_hex = "54A38E3B599E48C4F581FEC14B62EA29"
    ctr_hex = "00000000000000000000000000000000"

    string1 = "abc"
    encrypted_string1 = encrypt_string(string1, key_hex, ctr_hex)
    assert_equal string1.length * 2, encrypted_string1.length

    string2 = "abc123zxc"
    encrypted_string2 = encrypt_string(string2, key_hex, ctr_hex)
    assert_equal string2.length * 2, encrypted_string2.length
  end
end
