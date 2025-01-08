![](gmssl.svg)

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
类Random实现随机数生成功能，通过randBytes方法生成的是具备密码安全性的随机数，可以用于密钥、IV或者其他随机数生成器的随机种子。

```ruby
buf = FFI::MemoryPointer.new(:uint8, 256)
result = Random.rand_bytes(buf, 256)
puts result, buf.read_bytes(256).unpack('H*').first
```

### sm3 哈希
SM3密码杂凑函数可以将任意长度的输入数据计算为固定32字节长度的哈希值。

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

HMAC-SM3是基于SM3密码杂凑算法的消息认证码(MAC)算法，消息认证码算法可以看作带密钥的哈希函数，主要用于保护消息不受篡改。通信双方需要事先协商出一个密钥，比如32字节的随机字节序列，数据的发送方用这个密钥对消息计算MAC值，并且把MAC值附在消息后面。消息的接收方在收到消息后，用相同的密钥计算消息的MAC值，并且和发送消息附带的MAC值做对比，如果一致说明消息没有被篡改，如果不一致，说明消息被篡改了。

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

常用软件如Word、PDF、WinRAR等支持基于口令的文件加密，字符串形式的口令相对于随机的密钥字节序列对用户来说更容易记忆和输入，对用户更加友好。但是由于口令中存在的信息熵远低于随机的二进制密钥，直接将口令字符串作为密钥，甚至无法抵御来自个人计算机的暴力破解攻击。一种典型的错误用法是直接用哈希函数计算口令的哈希值，将看起来随机的哈希值作为密钥使用。但是由于口令的空间相对较小，攻击者仍然可以尝试所有可能口令的哈希值，对于暴力破解来说，破解口令的哈希值和原始口令，在攻击难度上没有太大差别。

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
