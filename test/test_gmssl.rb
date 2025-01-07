require "minitest/autorun"
require "gmssl"

class GmsslTest < Minitest::Test
  #  test path
  def test_root
    assert_includes __FILE__, GmSSL.root
  end

  #  test version
  def test_version_num
    assert_equal GmSSL::Version.gmssl_version_num, 30102
  end

  def test_version_str
    assert_equal GmSSL::Version.gmssl_version_str, 'GmSSL 3.1.2 Dev'
  end

  # test random
  def test_rand_bytes
    buf = FFI::MemoryPointer.new(:uint8, 256)
    result = GmSSL::Random.rand_bytes(buf, 256)
    assert_equal buf.read_bytes(256).unpack('H*').first.length, 512
  end
end
