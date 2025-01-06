require "minitest/autorun"
require "gmssl"

class GmsslTest < Minitest::Test
  def test_root
    assert_includes __FILE__, GmSSL.root
  end

  def test_version
    assert_equal GmSSL::Version.gmssl_version_num, 30102
  end
end
