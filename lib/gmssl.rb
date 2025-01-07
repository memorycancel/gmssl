# frozen_string_literal: true

LIB_FILE = 'libgmssl.so.3.1'

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
