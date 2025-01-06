Gem::Specification.new do |s|
  s.name        = "gmssl"
  s.version     = "1.0.0"
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
    "lib/gmssl/version.rb"
  ]

  s.files += Dir.glob([
    "GmSSL/build/bin/*"
  ])
end
