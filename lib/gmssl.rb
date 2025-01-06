# frozen_string_literal: true

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
