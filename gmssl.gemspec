# coding: utf-8
# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name        = "gmssl"
  s.version     = "1.1.2"
  s.summary     = "GmSSL ruby FFI"
  s.description = "GmSSL c to ruby FFI"
  s.authors     = ["memorycancel"]
  s.email       = "memorycancel@gmail.com"
  s.homepage    =
    "https://rubygems.org/gems/gmssl"
  s.license       = "MIT"
  s.required_ruby_version = ">= 3.0"

  s.files       = [
    "lib/gmssl.rb",
    "lib/gmssl/version.rb",
    "lib/gmssl/random.rb",
    "lib/gmssl/sm3.rb",
    "lib/gmssl/sm4.rb",
    "lib/gmssl/ghash.rb",
    "lib/gmssl/zuc.rb",
    "lib/gmssl/helper.rb"
  ]

  s.files += Dir.glob([
    "GmSSL/build/bin/*"
  ])

  s.files += Dir.glob([
    "test/helper.rb"
  ])
end
