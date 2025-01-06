# frozen_string_literal: true

require 'ffi'

module GmSSL
  module Version
    extend FFI::Library
    file = File.join GmSSL.lib, 'libgmssl.so.3.1'
    ffi_lib file
    attach_function :gmssl_version_num, [], :int
  end
end
