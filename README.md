![](gmssl.svg)

`gmssl` 是GmSSL密码库 `https://github.com/guanzhi/GmSSL` 的Ruby语言封装。
依赖ruby的`ffi`实现。

## 准备

```shell
# install cmake
sudo apt-get install cmake
# install https://mise.jdx.dev/
mise install ruby@3.4
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
