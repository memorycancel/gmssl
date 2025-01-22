# frozen_string_literal: true

require "minitest/autorun"
require "gmssl"
require "helper"

class GmsslServicesTest < Minitest::Test
  include GmSSL

  def test_version_info
    assert_equal Version.info, "VERSION: 30102, GmSSL 3.1.2 Dev"
  end

  def test_rand_bytes
    assert_equal Random.bytes(256).length, 512
  end

  def test_sm3_digest
    # echo -n abc | `pwd`/GmSSL/build/bin/gmssl sm3
    # 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
    sm3_bin_str =
      "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    assert_equal SM3.digest('abc'), sm3_bin_str
  end

  def test_sm3_hmac
    # KEY_HEX=`$PWD/GmSSL/build/bin/gmssl rand -outlen 16 -hex`
    # 54A38E3B599E48C4F581FEC14B62EA29
    # echo -n abc | `pwd`/GmSSL/build/bin/gmssl sm3hmac -key $KEY_HEX
    # 130eb2c6bc1e22cb1d7177089c59527e09aaa96a08fbaccf05c86dac034615b8
    res = SM3.hmac("54A38E3B599E48C4F581FEC14B62EA29", "abc")
    assert_equal res, "130eb2c6bc1e22cb1d7177089c59527e09aaa96a08fbaccf05c86dac034615b8"
  end

  def test_sm3_pbkdf2
    # `pwd`/GmSSL/build/bin/gmssl rand -outlen 8 -hex
    # 667D1BD0262E24E8
    # `pwd`/GmSSL/build/bin/gmssl sm3_pbkdf2 -pass P@ssw0rd -salt 667D1BD0262E24E8 -iter 10000 -outlen 16 -hex
    # dd4fd234a828135264c7c89c13b7e1b3

    psswd = "P@ssw0rd"
    hex_salt = "667D1BD0262E24E8"
    iterations = 10000
    outlen = 16 # Desired length of the output key
    assert_equal SM3.pbkdf2(psswd, hex_salt, iterations, outlen), "dd4fd234a828135264c7c89c13b7e1b3"
  end

  def test_sm4_cbc_encrypt_decrypt
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

    key = "117B5119CDFDD46288DAF9064414D801"  # 16 bytes key
    iv = "5428F71057DD4AD68C34E38BEA700309"   # 16 bytes IV
    plaintext = "Hello, sm4_cbc!"

    ciphertext = SM4.cbc_encrypt(key, iv, plaintext)
    assert_equal ciphertext, "4b6f370c339fc510c19a1a3f78460725"

    decrypted_text = SM4.cbc_decrypt(key, iv, ciphertext)
    assert_equal decrypted_text, "Hello, sm4_cbc!"
  end

  def test_sm4_ctr
    key_hex = "54A38E3B599E48C4F581FEC14B62EA29"
    ctr_hex = "00000000000000000000000000000000"
    string1 = "abc"
    encrypted_string1 = SM4.ctr_encrypt(string1, key_hex, ctr_hex)
    assert_equal string1.length * 2, encrypted_string1.length

    string2 = "abcd"
    encrypted_string2 = SM4.ctr_encrypt(string2, key_hex, ctr_hex)
    assert_equal string2.length * 2, encrypted_string2.length
  end

  def test_sm4_gcm
    # TEXT=hello_sm4_gcm                                #hello_sm4_gcm
    # KEY=`GmSSL/build/bin/gmssl rand -outlen 16 -hex`  #B789047EE36BD1DB9BCCD5B84D0E8C8D
    # IV=`GmSSL/build/bin/gmssl rand -outlen 12 -hex`   #F0F83C02897BE824AAB58361
    # AAD="The_AAD_Data"                                #The_AAD_Data
    # echo -n hello_sm4_gcm | \
    #  GmSSL/build/bin/gmssl sm4_gcm -encrypt \
    #    -key B789047EE36BD1DB9BCCD5B84D0E8C8D \
    #    -iv F0F83C02897BE824AAB58361 \
    #    -aad The_AAD_Data \
    #    -out sm4_gcm_ciphertext.bin

    # GmSSL/build/bin/gmssl sm4_gcm -decrypt \
    #    -key B789047EE36BD1DB9BCCD5B84D0E8C8D \
    #    -iv F0F83C02897BE824AAB58361 \
    #    -aad The_AAD_Data \
    #    -in sm4_gcm_ciphertext.bin
    # => hello_sm4_gcm

    key = "B789047EE36BD1DB9BCCD5B84D0E8C8D"  # 16 bytes key
    iv = "F0F83C02897BE824AAB58361"           # 12 bytes IV
    aad = "The_AAD_Data"
    input = "hello_sm4_gcm"
    encrypted_output, tag = SM4.gcm_encrypt(key, iv, aad, input)
    # puts "#{encrypted_output}, #{tag}"
    assert_equal encrypted_output, "f1e803c9acb94e458e1585ba55"
    assert_equal tag, "5fb0f06d28ac73775dcefb84e316646e"
    assert_equal SM4.gcm_decrypt(key, iv, aad, encrypted_output, tag), "hello_sm4_gcm"
  end

  # 6 测试祖冲之Zuc序列密码
  def test_zuc
    # GmSSL/build/bin/gmssl rand -outlen 20 -hex # TEXT: holazuc
    # GmSSL/build/bin/gmssl rand -outlen 16 -hex # KEY: 117B5119CDFDD46288DAF9064414D801
    # GmSSL/build/bin/gmssl rand -outlen 16 -hex # IV: 5428F71057DD4AD68C34E38BEA700309
    # echo -n holazuc | GmSSL/build/bin/gmssl zuc \
    #     -key 117B5119CDFDD46288DAF9064414D801 \
    #     -iv 5428F71057DD4AD68C34E38BEA700309 \
    #     -out zuc_ciphertext_out.bin

    # GmSSL/build/bin/gmssl zuc \
    #     -key 117B5119CDFDD46288DAF9064414D801 \
    #     -iv 5428F71057DD4AD68C34E38BEA700309 \
    #     -in zuc_ciphertext_out.bin

    key = "117B5119CDFDD46288DAF9064414D801"  # 16 bytes key
    iv = "5428F71057DD4AD68C34E38BEA700309"   # 16 bytes IV
    input = "zuc"
    encrypted_output = ZUC.encrypt(key, iv, input)
    assert_equal encrypted_output, "c4fee6"
    assert_equal ZUC.decrypt(key, iv, encrypted_output), "zuc"
  end
end
