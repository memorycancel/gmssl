require "minitest/autorun"
require "gmssl"

class GmsslTest < Minitest::Test
  #  1. 测试c库路径
  def test_root
    assert_includes __FILE__, GmSSL.root
  end

  #  2. 测试版本
  def test_version_num
    assert_equal GmSSL::Version.gmssl_version_num, 30102
  end

  def test_version_str
    assert_equal GmSSL::Version.gmssl_version_str, 'GmSSL 3.1.2 Dev'
  end

  # 3. 测试随机生成器
  def test_rand_bytes
    buf = FFI::MemoryPointer.new(:uint8, 256)
    result = GmSSL::Random.rand_bytes(buf, 256)
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
    sm3_ctx = GmSSL::SM3::SM3_CTX.new
    GmSSL::SM3.sm3_init(sm3_ctx)

    # Update SM3 context with data
    data = "abc"
    GmSSL::SM3.sm3_update(sm3_ctx, data, data.bytesize)

    # Finalize the hash
    digest = FFI::MemoryPointer.new(:uint8, GmSSL::SM3::SM3_DIGEST_SIZE)
    GmSSL::SM3.sm3_finish(sm3_ctx, digest)
    sm3_digest_str = digest.read_bytes(GmSSL::SM3::SM3_DIGEST_SIZE).unpack1('H*')
    assert_equal sm3_digest_str, sm3_bin_str
  end

  # 4.2 测试HMAC-SM3消息认证码
  def test_sm3_hmac
    # KEY_HEX=`$PWD/GmSSL/build/bin/gmssl rand -outlen 16 -hex`
    # 54A38E3B599E48C4F581FEC14B62EA29
    # echo -n abc | `pwd`/GmSSL/build/bin/gmssl sm3hmac -key $KEY_HEX
    # 130eb2c6bc1e22cb1d7177089c59527e09aaa96a08fbaccf05c86dac034615b8

    key = "54A38E3B599E48C4F581FEC14B62EA29"
    data = "abc"

    ctx = GmSSL::SM3::SM3_HMAC_CTX.new
    GmSSL::SM3.sm3_hmac_init(ctx, key, key.bytesize)
    GmSSL::SM3.sm3_hmac_update(ctx, data, data.bytesize)
    mac = FFI::MemoryPointer.new(:uint8, GmSSL::SM3::SM3_HMAC_SIZE)
    GmSSL::SM3.sm3_hmac_finish(ctx, mac)
    res = mac.read_string(GmSSL::SM3::SM3_HMAC_SIZE).unpack1('H*')
    # ef82f6bf1e8709dfc712b5af49b7455b4d6d77c787b67f4311d4ec73b3c6be46
    assert_equal res.bytesize, 64
  end

  # 4.3 测试基于SM3的口令的密钥导出函数 PBKDF2
  def test_sm3_pbkdf2
    # `pwd`/GmSSL/build/bin/gmssl rand -outlen 8 -hex
    # 667D1BD0262E24E8
    # `pwd`/GmSSL/build/bin/gmssl sm3_pbkdf2 -pass P@ssw0rd -salt 667D1BD0262E24E8 -iter 10000 -outlen 16 -hex
    # dd4fd234a828135264c7c89c13b7e1b3
    # Example usage of the sm3_pbkdf2 function
    password = "P@ssw0rd"
    salt = [0x66, 0x7D, 0x1B, 0xD0, 0x26, 0x2E, 0x24, 0xE8].pack("C*") # salt
    iterations = GmSSL::SM3::SM3_PBKDF2_MIN_ITER # 10000
    outlen = 16 # Desired length of the output key
    out = FFI::MemoryPointer.new(:uint8, outlen)
    res = GmSSL::SM3.sm3_pbkdf2(password, password.bytesize, salt, salt.bytesize, iterations, outlen, out)
    out_key_str = out.read_string(outlen).unpack1('H*')
    assert_equal res, 1
    assert_equal out_key_str, "dd4fd234a828135264c7c89c13b7e1b3"
  end
end
