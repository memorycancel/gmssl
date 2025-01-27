# frozen_string_literal: true

LIB_FILE = case Gem::Platform.local.os
when "darwin"
  "libgmssl.3.1.dylib"
when "linux"
  "libgmssl.so.3.1"
end

module GmSSL
  def self.root
    File.expand_path '../..', __FILE__
  end

  def self.bin
    File.join root, 'GmSSL/build/bin'
  end

  def self.lib
    bin
  end
end

require 'gmssl/version'
require 'gmssl/random'
require 'gmssl/sm3'
require 'gmssl/sm4'
require 'gmssl/zuc'
