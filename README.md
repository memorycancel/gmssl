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

### 随机数生成器
类Random实现随机数生成功能，通过randBytes方法生成的是具备密码安全性的随机数，可以用于密钥、IV或者其他随机数生成器的随机种子。

```ruby
buf = FFI::MemoryPointer.new(:uint8, 256)
result = GmSSL::Random.rand_bytes(buf, 256)
puts result, buf.read_bytes(256).unpack('H*').first
```

### SM3哈希
SM3密码杂凑函数可以将任意长度的输入数据计算为固定32字节长度的哈希值。

```ruby
# echo -n abc | `pwd`/GmSSL/build/bin/gmssl sm3
# 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

# Initialize SM3
sm3_ctx = GmSSL::SM3::SM3_CTX.new
GmSSL::SM3.sm3_init(sm3_ctx)

# Update SM3 context with data
data = "abc"
GmSSL::SM3.sm3_update(sm3_ctx, data, data.bytesize)

# Finalize the hash
digest = FFI::MemoryPointer.new(:uint8, GmSSL::SM3::SM3_DIGEST_SIZE)
GmSSL::SM3.sm3_finish(sm3_ctx, digest)
sm3_digest_str = digest.read_bytes(GmSSL::SM3::SM3_DIGEST_SIZE).unpack('H*').first
puts sm3_digest_str
```

###
