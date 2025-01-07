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
    sm3_digest_str = digest.read_bytes(GmSSL::SM3::SM3_DIGEST_SIZE).unpack('H*').first
    assert_equal sm3_digest_str, sm3_bin_str
  end

  # 4.2 测试HMAC-SM3消息认证码
end
