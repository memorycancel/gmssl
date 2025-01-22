![](../gmssl.svg)

`gmssl` 是GmSSL密码库 `https://github.com/guanzhi/GmSSL` 的Ruby语言封装。
依赖ruby的`ffi`实现。

## 准备

```shell
# install cmake
sudo apt-get install cmake
# install mise follow: https://mise.jdx.dev/installing-mise.html
mise install ruby@3.4
#required_ruby_version = ">= 3.0"
mise use -g ruby@3.4
```

## 安装

```shell
gem install bundler
git clone https://github.com/memorycancel/gmssl
cd gmssl
bundle install -V
bundle exec rake compile
bundle exec rake test
bash install_gem
```

## 使用

```ruby
require 'gmssl'

GmSSL::Version.gmssl_version_num
#=> 30102
```

## 声明

本项目是`start-up`阶段，stable版本推出前不可用于生产环境。

## LICENSE

本项目采用`MIT`协议。

## TODO

+ 兼容 Linux/MacOS/Windows 编译（目前支持 Linux)
+ 按SM2、SM3、SM4、SM9、ZUC逐次完成开发
+ 与Rails加密模块集成
+ 添加 ffi 测试

## 示例

在调用的代码块内 include GmSSL, 调用函数时可以省略前缀,例如:

```ruby
require 'gmssl'

include GmSSL
Version.gmssl_version_num
#=> 30102
```

等价于:
```ruby
require 'gmssl'
GmSSL::Version.gmssl_version_num
#=> 30102
```

以下示例默认`include GmSSL`,省略前缀`GmSSL::`:

### random 随机数生成器
random实现随机数生成功能，通过rand_bytes方法生成的是具备密码安全性的随机数，可以用于密钥、IV或者其他随机数生成器的`随机种子`。

```ruby
buf = FFI::MemoryPointer.new(:uint8, 256)
result = Random.rand_bytes(buf, 256)
puts result, buf.read_bytes(256).unpack('H*').first
```

### sm3 哈希
SM3密码杂凑函数可以将`任意长度`的输入数据计算为固定32字节长度的哈希值。

```ruby
# echo -n abc | `pwd`/GmSSL/build/bin/gmssl sm3
# 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

# Initialize SM3
sm3_ctx = SM3::SM3_CTX.new
SM3.sm3_init(sm3_ctx)

# Update SM3 context with data
data = "abc"
SM3.sm3_update(sm3_ctx, data, data.bytesize)

# Finalize the hash
digest = FFI::MemoryPointer.new(:uint8, SM3::SM3_DIGEST_SIZE)
SM3.sm3_finish(sm3_ctx, digest)
sm3_digest_str = digest.read_bytes(SM3::SM3_DIGEST_SIZE).unpack('H*').first
puts sm3_digest_str
```

### sm3_hmac 消息认证码

HMAC-SM3是基于SM3密码杂凑算法的消息认证码(MAC)算法，消息认证码算法可以看作带密钥的哈希函数，主要用于`保护消息不受篡改`。通信双方需要事先协商出一个密钥，比如32字节的随机字节序列，数据的发送方用这个密钥对消息计算MAC值，并且把MAC值附在消息后面。消息的接收方在收到消息后，用相同的密钥计算消息的MAC值，并且和发送消息附带的MAC值做对比，如果一致说明消息没有被篡改，如果不一致，说明消息被篡改了。

```ruby
# KEY_HEX=`$PWD/GmSSL/build/bin/gmssl rand -outlen 16 -hex`
# 54A38E3B599E48C4F581FEC14B62EA29
# echo -n abc | `pwd`/GmSSL/build/bin/gmssl sm3hmac -key $KEY_HEX
# 130eb2c6bc1e22cb1d7177089c59527e09aaa96a08fbaccf05c86dac034615b8

key = [
  0x54, 0xA3, 0x8E, 0x3B, 0x59, 0x9E, 0x48, 0xC4,
  0xF5, 0x81, 0xFE, 0xC1, 0x4B, 0x62, 0xEA, 0x29
].pack("C*")
data = "abc"

ctx = SM3::SM3_HMAC_CTX.new
SM3.sm3_hmac_init(ctx, key, key.bytesize)
SM3.sm3_hmac_update(ctx, data, data.bytesize)
mac = FFI::MemoryPointer.new(:uint8, SM3::SM3_HMAC_SIZE)
SM3.sm3_hmac_finish(ctx, mac)
res = mac.read_string(SM3::SM3_HMAC_SIZE).unpack1('H*')
```

### sm3_pbkdf2 基于SM3的口令密钥导出函数

常用软件如Word、PDF、WinRAR等支持基于口令的文件加密，字符串形式的口令相对于随机的密钥字节序列`对用户来说更容易记忆和输入，对用户更加友好`。但是由于口令中存在的信息熵远低于随机的二进制密钥，直接将口令字符串作为密钥，甚至无法抵御来自个人计算机的暴力破解攻击。一种典型的错误用法是直接用哈希函数计算口令的哈希值，将看起来随机的哈希值作为密钥使用。但是由于口令的空间相对较小，攻击者仍然可以尝试所有可能口令的哈希值，对于暴力破解来说，破解口令的哈希值和原始口令，在攻击难度上没有太大差别。

安全和规范的做法是采用一个基于口令的密钥导出函数(Password-Based Key Derivation Function, PBKDF)从口令中导出密钥。通过PBKDF导出密钥并不会降低攻击者在暴力破解时尝试的口令数量，但是可以防止攻击者通过查预计算表的方式来加速破解，并且可以大大增加攻击者尝试每一个可能口令的计算时间。PBKDF2是安全的并且使用广泛的PBKDF算法标准之一，算法采用哈希函数作为将口令映射为密钥的主要部件，通过加入随机并且公开的盐值(Salt)来抵御预计算，通过增加多轮的循环计算来增加在线破解的难度，并且支持可变的导出密钥长度。

```ruby
# `pwd`/GmSSL/build/bin/gmssl rand -outlen 8 -hex
# 667D1BD0262E24E8
# `pwd`/GmSSL/build/bin/gmssl sm3_pbkdf2 -pass P@ssw0rd -salt 667D1BD0262E24E8 -iter 10000 -outlen 16 -hex
# dd4fd234a828135264c7c89c13b7e1b3

password = "P@ssw0rd"
salt = [0x66, 0x7D, 0x1B, 0xD0, 0x26, 0x2E, 0x24, 0xE8].pack("C*") # salt
iterations = SM3::SM3_PBKDF2_MIN_ITER # 10000
outlen = 16 # Desired length of the output key
out = FFI::MemoryPointer.new(:uint8, outlen)
res = SM3.sm3_pbkdf2(password, password.bytesize, salt, salt.bytesize, iterations, outlen, out)
out_key_str = out.read_string(outlen).unpack1('H*')
```

### sm4 分组密码

SM4算法是分组密码算法，其密钥长度为128比特（16字节），分组长度为128比特（16字节）。SM4算法每次只能加密或者解密一个固定16字节长度的分组，不支持加解密任意长度的消息。分组密码通常作为更高层密码方案的一个组成部分，不适合普通上层应用调用。如果应用需要保护数据和消息，那么应该优先选择采用SM4-GCM模式，或者为了兼容已有的系统，也可以使用SM4-CBC或SM4-CTR模式。
多次调用Sm4的分组加密解密功能可以实现ECB模式，由于ECB模式在消息加密应用场景中并不安全，因此GmSSL中没有提供ECB模式。如果应用需要开发SM4的其他加密模式，也可基于SM4来开发这些模式。

### sm4_cbc 加密模式

CBC模式是应用最广泛的分组密码加密模式之一，虽然目前不建议在新的应用中继续使用CBC默认，为了`保证兼容性`，应用仍然可能需要使用CBC模式。

```ruby
# `pwd`/GmSSL/build/bin/gmssl rand -outlen 20 -hex # TEXT: hello
# `pwd`/GmSSL/build/bin/gmssl rand -outlen 16 -hex # KEY: 117B5119CDFDD46288DAF9064414D801
# `pwd`/GmSSL/build/bin/gmssl rand -outlen 16 -hex # IV: 5428F71057DD4AD68C34E38BEA700309
# echo -n hello | \
#     `pwd`/GmSSL/build/bin/gmssl sm4_cbc -encrypt \
#         -key 117B5119CDFDD46288DAF9064414D801 \
#         -iv 5428F71057DD4AD68C34E38BEA700309 \
#         -out sm4_cbc_ciphertext.bin

# `pwd`/GmSSL/build/bin/gmssl sm4_cbc -decrypt \
#      -key 117B5119CDFDD46288DAF9064414D801 \
#      -iv 5428F71057DD4AD68C34E38BEA700309 \
#      -in sm4_cbc_ciphertext.bin
# hello

def sm4_cbc_encrypt_decrypt(key, iv, plaintext)
  ctx = SM4::SM4_CBC_CTX.new

  # SM4 CBC Encrypt
  SM4.sm4_cbc_encrypt_init(ctx, key, iv)
  ciphertext = FFI::MemoryPointer.new(:uint8, plaintext.bytesize + SM4::SM4_BLOCK_SIZE)
  outlen = FFI::MemoryPointer.new(:size_t)
  SM4.sm4_cbc_encrypt_update(ctx, plaintext, plaintext.bytesize, ciphertext, outlen)
  ciphertext_len = outlen.read(:size_t)
  SM4.sm4_cbc_encrypt_finish(ctx, ciphertext + ciphertext_len, outlen)
  ciphertext_len += outlen.read(:size_t)

  # SM4 CBC Decrypt
  SM4.sm4_cbc_decrypt_init(ctx, key, iv)
  decrypted = FFI::MemoryPointer.new(:uint8, ciphertext_len + SM4::SM4_BLOCK_SIZE)
  outlen = FFI::MemoryPointer.new(:size_t)
  SM4.sm4_cbc_decrypt_update(ctx, ciphertext, ciphertext_len, decrypted, outlen)
  decrypted_len = outlen.read(:size_t)
  SM4.sm4_cbc_decrypt_finish(ctx, decrypted + decrypted_len, outlen)
  decrypted_len += outlen.read(:size_t)

  decrypted.read_bytes(decrypted_len)
end

key = "117B5119CDFDD46288DAF9064414D801"  # 16 bytes key
iv = "5428F71057DD4AD68C34E38BEA700309"   # 16 bytes IV
plaintext = "Hello, GmSSL!"

decrypted_text = sm4_cbc_encrypt_decrypt(key, iv, plaintext)
```

### sm4_ctr 加密模式

CTR加密模式可以加密任意长度的消息，和CBC模式不同，并不需要采用填充方案，因此SM4-CTR加密输出的密文长度和输入的明文`等长`。对于`存储或传输带宽有限的应用场景`，SM4-CTR相对SM4-CBC模式，密文`不会增加格外长度`。

```ruby
def encrypt_string(input_string, key_hex, ctr_hex)
  key = hex_string_to_packed_bytes(key_hex)
  ctr = hex_string_to_packed_bytes(ctr_hex)
  input_data = input_string.bytes.pack("C*")

  output_data = FFI::MemoryPointer.new(:uint8, input_data.bytesize)
  output_length = FFI::MemoryPointer.new(:size_t)

  key_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_KEY_SIZE)
  ctr_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_BLOCK_SIZE)
  key_ptr.put_array_of_uint8(0, key.bytes)
  ctr_ptr.put_array_of_uint8(0, ctr.bytes)

  ctx = SM4::SM4_CTR_CTX.new
  SM4.sm4_ctr_encrypt_init(ctx, key_ptr, ctr_ptr)
  SM4.sm4_ctr_encrypt_update(ctx, input_data, input_data.bytesize, output_data, output_length)
  SM4.sm4_ctr_encrypt_finish(ctx, output_data, output_length)

  encrypted_data = output_data.read_string(output_length.read(:size_t))
  encrypted_data.unpack("H*")[0] # Return hex string representation of encrypted data
end

key_hex = "54A38E3B599E48C4F581FEC14B62EA29"
ctr_hex = "00000000000000000000000000000000"

string1 = "abc"
encrypted_string1 = encrypt_string(string1, key_hex, ctr_hex)
# assert_equal string1.length * 2, encrypted_string1.length
```

### sm4_gcm 认证加密模式

SM4的GCM模式是一种认证加密模式，和CBC、CTR等加密模式的主要区别在于，GCM模式的加密过程默认在密文最后添加完整性标签，也就是MAC标签，因此应用在采用SM4-GCM模式时，没有必要再计算并添加SM3-HMAC了。在有的应用场景中，比如对消息报文进行加密，对于消息头部的一段数据（报头字段）只需要做完整性保护，不需要加密，SM4-GCM支持这种场景。在Sm4Gcm类的init方法中，除了key、iv参数，还可以提供aad字节数字用于提供不需要加密的消息头部数据。

```ruby
# TEXT=hello_sm4_gcm                                #hello_sm4_gcm
# KEY=`GmSSL/build/bin/gmssl rand -outlen 16 -hex`  #B789047EE36BD1DB9BCCD5B84D0E8C8D
# IV=`GmSSL/build/bin/gmssl rand -outlen 12 -hex`   #F0F83C02897BE824AAB58361
# AAD="The_AAD_Data"                                #The_AAD_Data
# echo -n hello_sm4_gcm | \
#  GmSSL/build/bin/gmssl sm4_gcm -encrypt \
#    -key B789047EE36BD1DB9BCCD5B84D0E8C8D \
#    -iv F0F83C02897BE824AAB58361 \
#    -aad The_AAD_Data \
#    -out sm4_gcm_ciphertext.bin

# GmSSL/build/bin/gmssl sm4_gcm -decrypt \
#    -key B789047EE36BD1DB9BCCD5B84D0E8C8D \
#    -iv F0F83C02897BE824AAB58361 \
#    -aad The_AAD_Data \
#    -in sm4_gcm_ciphertext.bin
# => hello_sm4_gcm
def sm4_gcm_encrypt_decrypt(key, iv, aad, input)
  key = hex_string_to_packed_bytes key
  iv = hex_string_to_packed_bytes iv
  key_struct = SM4::SM4_KEY.new
  key_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_KEY_SIZE)
  key_ptr.put_array_of_uint8(0, key.bytes)
  SM4::sm4_set_encrypt_key(key_struct, key_ptr)

  iv_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_BLOCK_SIZE)
  iv_ptr.put_array_of_uint8(0, iv.bytes)

  aad_ptr = FFI::MemoryPointer.new(:uint8, aad.bytesize)
  aad_ptr.put_array_of_uint8(0, aad.bytes)

  input_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
  input_ptr.put_array_of_uint8(0, input.bytes)

  output_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
  tag_ptr = FFI::MemoryPointer.new(:uint8, SM4::SM4_GCM_MAX_TAG_SIZE)

  SM4::sm4_gcm_encrypt(key_struct, iv_ptr, iv.bytesize, aad_ptr, aad.bytesize, input_ptr, input.bytesize, output_ptr, SM4::SM4_GCM_MAX_TAG_SIZE, tag_ptr)
  encrypted_output = output_ptr.read_string(input.bytesize)
  tag = tag_ptr.read_string(SM4::SM4_GCM_MAX_TAG_SIZE)

  decrypted_output_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
  SM4::sm4_gcm_decrypt(key_struct, iv_ptr, iv.bytesize, aad_ptr, aad.bytesize, output_ptr, input.bytesize, tag_ptr, SM4::SM4_GCM_MAX_TAG_SIZE, decrypted_output_ptr)
  decrypted_output = decrypted_output_ptr.read_string(input.bytesize)

  return encrypted_output, tag, decrypted_output
end

key = "B789047EE36BD1DB9BCCD5B84D0E8C8D"  # 16 bytes key
iv = "F0F83C02897BE824AAB58361"           # 12 bytes IV
aad = "The_AAD_Data"
input = "hello_sm4_gcm"

encrypted_output, tag, decrypted_output = sm4_gcm_encrypt_decrypt(key, iv, aad, input)
```

### 祖冲之序列密码

祖冲之密码算法(ZU Cipher, ZUC)是一种序列密码，密钥和IV长度均为16字节。作为序列密码ZUC可以加密可变长度的输入数据，并且输出的密文数据长度和输入数据等长，因此适合不允许密文膨胀的应用场景。在国密算法体系中，ZUC算法的设计晚于SM4，在32位通用处理器上通常比SM4-CBC明显要快。

在安全性方面，不建议在一组密钥和IV的情况下用ZUC算法加密大量的数据（比如GB级或TB级），避免序列密码超长输出时安全性降低。另外ZUC算法本身并不支持数据的完整性保护，因此在采用ZUC算法加密应用数据时，应考虑配合HMAC-SM3提供完整性保护。

```ruby
# GmSSL/build/bin/gmssl rand -outlen 20 -hex # TEXT: holazuc
# GmSSL/build/bin/gmssl rand -outlen 16 -hex # KEY: 117B5119CDFDD46288DAF9064414D801
# GmSSL/build/bin/gmssl rand -outlen 16 -hex # IV: 5428F71057DD4AD68C34E38BEA700309
# echo -n holazuc | GmSSL/build/bin/gmssl zuc \
#     -key 117B5119CDFDD46288DAF9064414D801 \
#     -iv 5428F71057DD4AD68C34E38BEA700309 \
#     -out zuc_ciphertext_out.bin

# GmSSL/build/bin/gmssl zuc \
#     -key 117B5119CDFDD46288DAF9064414D801 \
#     -iv 5428F71057DD4AD68C34E38BEA700309 \
#     -in zuc_ciphertext_out.bin

def zuc_encrypt_decrypt(key, iv, input)
  key = hex_string_to_packed_bytes key
  iv = hex_string_to_packed_bytes iv

  key_ptr = FFI::MemoryPointer.new(:uint8, ZUC::ZUC_KEY_SIZE)
  key_ptr.put_array_of_uint8(0, key.bytes)
  iv_ptr = FFI::MemoryPointer.new(:uint8, ZUC::ZUC_IV_SIZE)
  iv_ptr.put_array_of_uint8(0, iv.bytes)

  # Encrypt
  ctx = ZUC::ZUC_CTX.new
  ZUC::zuc_encrypt_init(ctx, key_ptr, iv_ptr)
  input_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
  input_ptr.put_array_of_uint8(0, input.bytes)
  output_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
  outlen_ptr = FFI::MemoryPointer.new(:size_t)
  ZUC::zuc_encrypt_update(ctx, input_ptr, input.bytesize, output_ptr, outlen_ptr)
  ZUC::zuc_encrypt_finish(ctx, output_ptr, outlen_ptr)
  encrypted_output = output_ptr.get_array_of_uint8(0, input.bytesize)

  # Decrypt
  ctx = ZUC::ZUC_CTX.new
  ZUC::zuc_encrypt_init(ctx, key_ptr, iv_ptr)
  encrypted_input_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
  encrypted_input_ptr.put_array_of_uint8(0, encrypted_output)
  decrypted_output_ptr = FFI::MemoryPointer.new(:uint8, input.bytesize)
  ZUC::zuc_encrypt_update(ctx, encrypted_input_ptr, input.bytesize, decrypted_output_ptr, outlen_ptr)
  ZUC::zuc_encrypt_finish(ctx, decrypted_output_ptr, outlen_ptr)
  decrypted_output = decrypted_output_ptr.get_array_of_uint8(0, input.bytesize)

  { encrypted: encrypted_output.pack('C*'), decrypted: decrypted_output.pack('C*') }
end

key = "117B5119CDFDD46288DAF9064414D801"  # 16 bytes key
iv = "5428F71057DD4AD68C34E38BEA700309"   # 16 bytes IV
input = "zuc"

result = zuc_encrypt_decrypt(key, iv, input)
```