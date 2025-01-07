# frozen_string_literal: true

require 'ffi'

module GmSSL
  module Version
    extend FFI::Library
    file = File.join GmSSL.lib, LIB_FILE
    ffi_lib file

    attach_function :gmssl_version_num, [], :int
    attach_function :gmssl_version_str, [], :string
  end
end
